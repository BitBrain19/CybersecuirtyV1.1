"""Real-time Streaming Prediction System

This module provides real-time streaming capabilities for ML models,
allowing continuous processing of data streams with low latency.
"""

import time
import json
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Callable, AsyncGenerator
from dataclasses import dataclass, asdict
from collections import deque
from concurrent.futures import ThreadPoolExecutor
import threading
from queue import Queue, Empty

import numpy as np
import pandas as pd
from kafka import KafkaConsumer, KafkaProducer
import redis
from websockets.server import serve
from websockets.exceptions import ConnectionClosed

from ..core.exceptions import StreamingError
from ..core.config import get_config
from ..monitoring.model_health import get_health_monitor

logger = logging.getLogger(__name__)

@dataclass
class StreamMessage:
    """Container for streaming messages."""
    id: str
    timestamp: float
    data: Dict[str, Any]
    source: str
    message_type: str
    priority: int = 1  # 1=high, 2=medium, 3=low

@dataclass
class PredictionResult:
    """Container for prediction results."""
    message_id: str
    model_name: str
    prediction: Any
    confidence: float
    processing_time: float
    timestamp: float
    metadata: Dict[str, Any]

class StreamBuffer:
    """Thread-safe buffer for streaming data."""
    
    def __init__(self, max_size: int = 10000):
        self.buffer = deque(maxlen=max_size)
        self.lock = threading.Lock()
        self.condition = threading.Condition(self.lock)
    
    def put(self, item: StreamMessage) -> None:
        """Add item to buffer."""
        with self.condition:
            self.buffer.append(item)
            self.condition.notify()
    
    def get(self, timeout: float = 1.0) -> Optional[StreamMessage]:
        """Get item from buffer with timeout."""
        with self.condition:
            if not self.buffer:
                self.condition.wait(timeout)
            
            if self.buffer:
                return self.buffer.popleft()
            return None
    
    def get_batch(self, batch_size: int = 10, timeout: float = 1.0) -> List[StreamMessage]:
        """Get batch of items from buffer."""
        batch = []
        with self.condition:
            # Wait for at least one item
            if not self.buffer:
                self.condition.wait(timeout)
            
            # Collect batch
            while self.buffer and len(batch) < batch_size:
                batch.append(self.buffer.popleft())
        
        return batch
    
    def size(self) -> int:
        """Get current buffer size."""
        with self.lock:
            return len(self.buffer)

class StreamProcessor:
    """Real-time stream processing engine."""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or get_config().get('streaming', {})
        self.models: Dict[str, Any] = {}
        self.preprocessors: Dict[str, Callable] = {}
        self.postprocessors: Dict[str, Callable] = {}
        
        # Streaming infrastructure
        self.input_buffer = StreamBuffer(max_size=self.config.get('buffer_size', 10000))
        self.output_buffer = StreamBuffer(max_size=self.config.get('buffer_size', 10000))
        
        # Processing control
        self.processing_active = False
        self.worker_threads: List[threading.Thread] = []
        self.executor = ThreadPoolExecutor(max_workers=self.config.get('max_workers', 4))
        
        # Metrics and monitoring
        self.health_monitor = get_health_monitor()
        self.processing_stats = {
            'messages_processed': 0,
            'messages_failed': 0,
            'avg_processing_time': 0.0,
            'throughput': 0.0
        }
        self.recent_times = deque(maxlen=1000)
        
        # External connections
        self.kafka_consumer: Optional[KafkaConsumer] = None
        self.kafka_producer: Optional[KafkaProducer] = None
        self.redis_client: Optional[redis.Redis] = None
        
        logger.info("Stream processor initialized")
    
    def register_model(self, name: str, model: Any, 
                      preprocessor: Optional[Callable] = None,
                      postprocessor: Optional[Callable] = None) -> None:
        """Register a model for streaming predictions."""
        self.models[name] = model
        if preprocessor:
            self.preprocessors[name] = preprocessor
        if postprocessor:
            self.postprocessors[name] = postprocessor
        
        logger.info(f"Registered model {name} for streaming")
    
    def start_processing(self, num_workers: int = 2) -> None:
        """Start stream processing workers."""
        if self.processing_active:
            logger.warning("Processing already active")
            return
        
        self.processing_active = True
        
        # Start worker threads
        for i in range(num_workers):
            worker = threading.Thread(
                target=self._processing_worker,
                args=(f"worker-{i}",),
                daemon=True
            )
            worker.start()
            self.worker_threads.append(worker)
        
        # Start metrics updater
        metrics_thread = threading.Thread(
            target=self._update_metrics,
            daemon=True
        )
        metrics_thread.start()
        self.worker_threads.append(metrics_thread)
        
        logger.info(f"Started {num_workers} processing workers")
    
    def stop_processing(self) -> None:
        """Stop stream processing."""
        self.processing_active = False
        
        # Wait for workers to finish
        for worker in self.worker_threads:
            worker.join(timeout=5)
        
        self.worker_threads.clear()
        self.executor.shutdown(wait=True)
        
        logger.info("Stopped stream processing")
    
    def _processing_worker(self, worker_id: str) -> None:
        """Main processing worker loop."""
        logger.info(f"Started processing worker {worker_id}")
        
        while self.processing_active:
            try:
                # Get batch of messages
                messages = self.input_buffer.get_batch(
                    batch_size=self.config.get('batch_size', 5),
                    timeout=1.0
                )
                
                if not messages:
                    continue
                
                # Process batch
                for message in messages:
                    try:
                        result = self._process_message(message)
                        if result:
                            self.output_buffer.put(result)
                            self.processing_stats['messages_processed'] += 1
                    except Exception as e:
                        logger.error(f"Error processing message {message.id}: {str(e)}")
                        self.processing_stats['messages_failed'] += 1
                
            except Exception as e:
                logger.error(f"Error in worker {worker_id}: {str(e)}")
                time.sleep(1)
        
        logger.info(f"Stopped processing worker {worker_id}")
    
    def _process_message(self, message: StreamMessage) -> Optional[PredictionResult]:
        """Process a single message."""
        start_time = time.time()
        
        try:
            # Determine which model to use based on message type
            model_name = self._select_model(message)
            if not model_name or model_name not in self.models:
                logger.warning(f"No suitable model for message type {message.message_type}")
                return None
            
            model = self.models[model_name]
            
            # Preprocess data
            processed_data = self._preprocess_data(message.data, model_name)
            if processed_data is None:
                logger.warning(f"Preprocessing failed for message {message.id}")
                return None
            
            # Make prediction
            prediction = model.predict(processed_data)
            
            # Extract confidence if available
            confidence = 1.0
            if hasattr(model, 'predict_proba'):
                try:
                    proba = model.predict_proba(processed_data)
                    confidence = float(np.max(proba))
                except:
                    pass
            elif isinstance(prediction, dict) and 'confidence' in prediction:
                confidence = prediction['confidence']
                prediction = prediction.get('prediction', prediction)
            
            # Postprocess result
            final_prediction = self._postprocess_result(prediction, model_name)
            
            processing_time = time.time() - start_time
            self.recent_times.append(processing_time)
            
            # Record prediction for monitoring
            self.health_monitor.record_prediction(
                model_name, processing_time, confidence
            )
            
            return PredictionResult(
                message_id=message.id,
                model_name=model_name,
                prediction=final_prediction,
                confidence=confidence,
                processing_time=processing_time,
                timestamp=time.time(),
                metadata={
                    'source': message.source,
                    'message_type': message.message_type,
                    'priority': message.priority
                }
            )
            
        except Exception as e:
            logger.error(f"Prediction failed for message {message.id}: {str(e)}")
            # Record error for monitoring
            if 'model_name' in locals():
                self.health_monitor.record_prediction(
                    model_name, time.time() - start_time, 0.0, error=True
                )
            return None
    
    def _select_model(self, message: StreamMessage) -> Optional[str]:
        """Select appropriate model based on message type."""
        message_type = message.message_type.lower()
        
        if 'threat' in message_type or 'attack' in message_type:
            return 'threat_detection'
        elif 'vulnerability' in message_type or 'vuln' in message_type:
            return 'vulnerability_assessment'
        
        # Default to first available model
        return next(iter(self.models.keys())) if self.models else None
    
    def _preprocess_data(self, data: Dict[str, Any], model_name: str) -> Optional[np.ndarray]:
        """Preprocess data for model input."""
        try:
            if model_name in self.preprocessors:
                return self.preprocessors[model_name](data)
            
            # Default preprocessing
            if isinstance(data, dict):
                # Convert dict to feature vector
                features = []
                for key in sorted(data.keys()):
                    value = data[key]
                    if isinstance(value, (int, float)):
                        features.append(float(value))
                    elif isinstance(value, str):
                        # Simple string encoding (hash-based)
                        features.append(float(hash(value) % 1000) / 1000.0)
                    else:
                        features.append(0.0)
                
                return np.array(features).reshape(1, -1)
            
            elif isinstance(data, (list, np.ndarray)):
                return np.array(data).reshape(1, -1)
            
            else:
                logger.warning(f"Unsupported data type for preprocessing: {type(data)}")
                return None
                
        except Exception as e:
            logger.error(f"Preprocessing error: {str(e)}")
            return None
    
    def _postprocess_result(self, prediction: Any, model_name: str) -> Any:
        """Postprocess prediction result."""
        try:
            if model_name in self.postprocessors:
                return self.postprocessors[model_name](prediction)
            
            # Default postprocessing
            if isinstance(prediction, np.ndarray):
                if prediction.size == 1:
                    return float(prediction.item())
                else:
                    return prediction.tolist()
            
            return prediction
            
        except Exception as e:
            logger.error(f"Postprocessing error: {str(e)}")
            return prediction
    
    def _update_metrics(self) -> None:
        """Update processing metrics."""
        last_processed = 0
        last_time = time.time()
        
        while self.processing_active:
            try:
                time.sleep(10)  # Update every 10 seconds
                
                current_time = time.time()
                current_processed = self.processing_stats['messages_processed']
                
                # Calculate throughput
                time_diff = current_time - last_time
                message_diff = current_processed - last_processed
                
                if time_diff > 0:
                    self.processing_stats['throughput'] = message_diff / time_diff
                
                # Calculate average processing time
                if self.recent_times:
                    self.processing_stats['avg_processing_time'] = np.mean(self.recent_times)
                
                last_processed = current_processed
                last_time = current_time
                
            except Exception as e:
                logger.error(f"Error updating metrics: {str(e)}")
    
    def add_message(self, data: Dict[str, Any], message_type: str, 
                   source: str = "api", priority: int = 1) -> str:
        """Add a message to the processing queue."""
        message_id = f"{int(time.time() * 1000000)}_{hash(str(data)) % 10000}"
        
        message = StreamMessage(
            id=message_id,
            timestamp=time.time(),
            data=data,
            source=source,
            message_type=message_type,
            priority=priority
        )
        
        self.input_buffer.put(message)
        return message_id
    
    def get_result(self, timeout: float = 5.0) -> Optional[PredictionResult]:
        """Get a prediction result."""
        return self.output_buffer.get(timeout)
    
    def get_results_batch(self, batch_size: int = 10, timeout: float = 1.0) -> List[PredictionResult]:
        """Get batch of prediction results."""
        return self.output_buffer.get_batch(batch_size, timeout)
    
    async def process_stream_async(self, data_stream: AsyncGenerator[Dict[str, Any], None],
                                 message_type: str) -> AsyncGenerator[PredictionResult, None]:
        """Process an async data stream."""
        async for data in data_stream:
            message_id = self.add_message(data, message_type, source="stream")
            
            # Wait for result
            start_time = time.time()
            while time.time() - start_time < 10:  # 10 second timeout
                result = self.get_result(timeout=0.1)
                if result and result.message_id == message_id:
                    yield result
                    break
                await asyncio.sleep(0.01)
    
    def setup_kafka_consumer(self, topics: List[str], **kwargs) -> None:
        """Setup Kafka consumer for streaming input."""
        try:
            self.kafka_consumer = KafkaConsumer(
                *topics,
                bootstrap_servers=self.config.get('kafka_servers', ['localhost:9092']),
                value_deserializer=lambda x: json.loads(x.decode('utf-8')),
                **kwargs
            )
            
            # Start consumer thread
            consumer_thread = threading.Thread(
                target=self._kafka_consumer_loop,
                daemon=True
            )
            consumer_thread.start()
            self.worker_threads.append(consumer_thread)
            
            logger.info(f"Setup Kafka consumer for topics: {topics}")
            
        except Exception as e:
            logger.error(f"Failed to setup Kafka consumer: {str(e)}")
    
    def _kafka_consumer_loop(self) -> None:
        """Kafka consumer loop."""
        if not self.kafka_consumer:
            return
        
        try:
            for message in self.kafka_consumer:
                if not self.processing_active:
                    break
                
                try:
                    data = message.value
                    message_type = data.get('type', 'unknown')
                    
                    self.add_message(
                        data.get('data', data),
                        message_type,
                        source='kafka',
                        priority=data.get('priority', 2)
                    )
                    
                except Exception as e:
                    logger.error(f"Error processing Kafka message: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Kafka consumer error: {str(e)}")
    
    def setup_kafka_producer(self, **kwargs) -> None:
        """Setup Kafka producer for streaming output."""
        try:
            self.kafka_producer = KafkaProducer(
                bootstrap_servers=self.config.get('kafka_servers', ['localhost:9092']),
                value_serializer=lambda x: json.dumps(x).encode('utf-8'),
                **kwargs
            )
            
            # Start producer thread
            producer_thread = threading.Thread(
                target=self._kafka_producer_loop,
                daemon=True
            )
            producer_thread.start()
            self.worker_threads.append(producer_thread)
            
            logger.info("Setup Kafka producer")
            
        except Exception as e:
            logger.error(f"Failed to setup Kafka producer: {str(e)}")
    
    def _kafka_producer_loop(self) -> None:
        """Kafka producer loop."""
        if not self.kafka_producer:
            return
        
        try:
            while self.processing_active:
                results = self.get_results_batch(batch_size=10, timeout=1.0)
                
                for result in results:
                    try:
                        topic = f"predictions_{result.model_name}"
                        self.kafka_producer.send(topic, asdict(result))
                        
                    except Exception as e:
                        logger.error(f"Error sending result to Kafka: {str(e)}")
                
        except Exception as e:
            logger.error(f"Kafka producer error: {str(e)}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processing statistics."""
        return {
            'processing_active': self.processing_active,
            'registered_models': list(self.models.keys()),
            'input_buffer_size': self.input_buffer.size(),
            'output_buffer_size': self.output_buffer.size(),
            'worker_threads': len(self.worker_threads),
            'stats': self.processing_stats.copy()
        }

# Global processor instance
_processor_instance: Optional[StreamProcessor] = None

def get_stream_processor() -> StreamProcessor:
    """Get global stream processor instance."""
    global _processor_instance
    if _processor_instance is None:
        _processor_instance = StreamProcessor()
    return _processor_instance