"""
Distributed Streaming Pipeline Module
Real-time ingestion via Kafka/Spark Streaming with stateful stream processors
"""

import asyncio
import json
import logging
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Callable, Awaitable
from collections import deque, defaultdict
import queue
import uuid

logger = logging.getLogger(__name__)


class StreamMessageType(str, Enum):
    """Types of stream messages"""
    EVENT = "event"
    ALERT = "alert"
    METRIC = "metric"
    CONTROL = "control"
    CHECKPOINT = "checkpoint"


class StreamStatus(str, Enum):
    """Stream processor status"""
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPED = "stopped"
    ERRORED = "errored"


@dataclass
class StreamMessage:
    """Message in the streaming pipeline"""
    message_id: str
    message_type: StreamMessageType
    timestamp: datetime
    source: str
    payload: Dict[str, Any]
    partition_key: Optional[str] = None
    priority: int = 0  # 0=low, 9=high
    retry_count: int = 0
    max_retries: int = 3
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'message_id': self.message_id,
            'message_type': self.message_type.value,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source,
            'payload': self.payload,
            'partition_key': self.partition_key,
            'priority': self.priority
        }


@dataclass
class StreamPartition:
    """Stream partition for distributed processing"""
    partition_id: int
    shard_key: str
    messages: deque = field(default_factory=lambda: deque(maxlen=10000))
    offset: int = 0
    committed_offset: int = 0
    last_processed_time: datetime = field(default_factory=datetime.now)
    processing_stats: Dict[str, int] = field(default_factory=lambda: defaultdict(int))


@dataclass
class StreamCheckpoint:
    """Checkpoint for recovery"""
    checkpoint_id: str
    partition_id: int
    offset: int
    timestamp: datetime
    state: Dict[str, Any]


class StatefulStreamProcessor:
    """Processes stream messages with state management"""
    
    def __init__(self, processor_name: str):
        self.processor_name = processor_name
        self.state: Dict[str, Any] = {}
        self.status = StreamStatus.INITIALIZING
        self.processed_count = 0
        self.error_count = 0
        self.last_checkpoint: Optional[StreamCheckpoint] = None
        self._lock = threading.RLock()
        self._message_handlers: Dict[StreamMessageType, Callable] = {}
    
    def register_handler(self, message_type: StreamMessageType, 
                        handler: Callable[[StreamMessage], Awaitable[Dict[str, Any]]]):
        """Register handler for message type"""
        self._message_handlers[message_type] = handler
    
    async def process_message(self, message: StreamMessage) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """Process a stream message"""
        try:
            with self._lock:
                handler = self._message_handlers.get(message.message_type)
                if not handler:
                    logger.warning(f"No handler for message type: {message.message_type}")
                    return False, None
                
                result = await handler(message)
                self.processed_count += 1
                self.status = StreamStatus.RUNNING
                
                return True, result
        except Exception as e:
            logger.error(f"Error processing message {message.message_id}: {e}")
            self.error_count += 1
            if self.error_count > 10:
                self.status = StreamStatus.ERRORED
            return False, None
    
    def get_state(self, key: str) -> Optional[Any]:
        """Get state value"""
        with self._lock:
            return self.state.get(key)
    
    def set_state(self, key: str, value: Any):
        """Set state value"""
        with self._lock:
            self.state[key] = value
    
    def create_checkpoint(self, partition_id: int, offset: int) -> StreamCheckpoint:
        """Create recovery checkpoint"""
        with self._lock:
            checkpoint = StreamCheckpoint(
                checkpoint_id=f"ckpt_{partition_id}_{offset}_{datetime.now().timestamp()}",
                partition_id=partition_id,
                offset=offset,
                timestamp=datetime.now(),
                state=self.state.copy()
            )
            self.last_checkpoint = checkpoint
            return checkpoint
    
    def restore_from_checkpoint(self, checkpoint: StreamCheckpoint):
        """Restore state from checkpoint"""
        with self._lock:
            self.state = checkpoint.state.copy()
            logger.info(f"Restored processor state from checkpoint {checkpoint.checkpoint_id}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get processor metrics"""
        with self._lock:
            return {
                'processor_name': self.processor_name,
                'status': self.status.value,
                'processed_count': self.processed_count,
                'error_count': self.error_count,
                'error_rate': self.error_count / (self.processed_count + 1),
                'state_size': len(self.state),
                'last_checkpoint': self.last_checkpoint.checkpoint_id if self.last_checkpoint else None
            }


class StreamPartitionManager:
    """Manages stream partitions for distributed processing"""
    
    def __init__(self, num_partitions: int = 8):
        self.partitions: Dict[int, StreamPartition] = {
            i: StreamPartition(partition_id=i, shard_key=f"shard_{i}")
            for i in range(num_partitions)
        }
        self.rebalance_history = deque(maxlen=100)
        self._lock = threading.RLock()
    
    def get_partition_for_key(self, key: str) -> int:
        """Get partition ID for a key"""
        return hash(key) % len(self.partitions)
    
    def append_message(self, message: StreamMessage):
        """Append message to appropriate partition"""
        partition_id = self.get_partition_for_key(
            message.partition_key or message.source
        )
        
        with self._lock:
            partition = self.partitions[partition_id]
            partition.messages.append(message)
            partition.offset += 1
            partition.processing_stats['total_messages'] += 1
    
    def get_partition_stats(self) -> Dict[int, Dict[str, Any]]:
        """Get statistics for all partitions"""
        stats = {}
        with self._lock:
            for pid, partition in self.partitions.items():
                stats[pid] = {
                    'partition_id': pid,
                    'queue_size': len(partition.messages),
                    'offset': partition.offset,
                    'committed_offset': partition.committed_offset,
                    'lag': partition.offset - partition.committed_offset,
                    'stats': dict(partition.processing_stats)
                }
        return stats
    
    def rebalance_partitions(self):
        """Rebalance partitions across consumers"""
        with self._lock:
            # Calculate load per partition
            loads = {}
            for pid, partition in self.partitions.items():
                loads[pid] = len(partition.messages)
            
            # Simple rebalancing: redistribute messages from overloaded partitions
            max_load = max(loads.values()) if loads else 0
            avg_load = sum(loads.values()) / len(loads) if loads else 0
            
            if max_load > avg_load * 1.5:  # Imbalance threshold
                logger.info(f"Rebalancing partitions: max_load={max_load}, avg_load={avg_load:.1f}")
                self.rebalance_history.append({
                    'timestamp': datetime.now().isoformat(),
                    'reason': 'load_imbalance',
                    'loads_before': loads.copy()
                })


class MicroBatchProcessor:
    """Micro-batching engine for efficient processing"""
    
    def __init__(self, batch_size: int = 100, batch_timeout_ms: int = 1000):
        self.batch_size = batch_size
        self.batch_timeout_ms = batch_timeout_ms
        self.current_batch: List[StreamMessage] = []
        self.batch_creation_time = time.time()
        self._lock = threading.RLock()
        self.batches_processed = 0
        self.total_messages = 0
    
    def add_message(self, message: StreamMessage) -> bool:
        """Add message to current batch"""
        with self._lock:
            self.current_batch.append(message)
            self.total_messages += 1
            
            if len(self.current_batch) >= self.batch_size:
                return True  # Batch ready
            
            elapsed_ms = (time.time() - self.batch_creation_time) * 1000
            if elapsed_ms > self.batch_timeout_ms and len(self.current_batch) > 0:
                return True  # Timeout triggered
            
            return False
    
    def get_batch(self) -> Optional[List[StreamMessage]]:
        """Get current batch if ready"""
        with self._lock:
            if len(self.current_batch) == 0:
                return None
            
            batch = self.current_batch[:]
            self.current_batch = []
            self.batch_creation_time = time.time()
            self.batches_processed += 1
            
            return batch
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get micro-batch metrics"""
        with self._lock:
            return {
                'batch_size_config': self.batch_size,
                'batch_timeout_ms': self.batch_timeout_ms,
                'batches_processed': self.batches_processed,
                'total_messages': self.total_messages,
                'current_batch_size': len(self.current_batch),
                'avg_messages_per_batch': self.total_messages / max(1, self.batches_processed)
            }


@dataclass
class StreamPipelineMetrics:
    """Metrics for stream pipeline"""
    total_messages_ingested: int = 0
    total_messages_processed: int = 0
    total_messages_failed: int = 0
    latency_p50_ms: float = 0.0
    latency_p95_ms: float = 0.0
    latency_p99_ms: float = 0.0
    throughput_msg_per_sec: float = 0.0
    total_runtime_seconds: float = 0.0


class DistributedStreamingPipeline:
    """Main distributed streaming pipeline"""
    
    def __init__(self, num_partitions: int = 8, batch_size: int = 100):
        self.status = StreamStatus.INITIALIZING
        self.partition_manager = StreamPartitionManager(num_partitions)
        self.micro_batcher = MicroBatchProcessor(batch_size)
        self.processors: Dict[str, StatefulStreamProcessor] = {}
        self.message_queue: queue.Queue = queue.Queue(maxsize=10000)
        self.metrics = StreamPipelineMetrics()
        self._lock = threading.RLock()
        self._running = False
        self._start_time = datetime.now()
    
    def register_processor(self, name: str) -> StatefulStreamProcessor:
        """Register a stream processor"""
        processor = StatefulStreamProcessor(name)
        with self._lock:
            self.processors[name] = processor
        return processor
    
    def ingest_message(self, message: StreamMessage) -> bool:
        """Ingest message into pipeline"""
        try:
            self.message_queue.put_nowait(message)
            self.partition_manager.append_message(message)
            self.metrics.total_messages_ingested += 1
            
            # Micro-batching
            if self.micro_batcher.add_message(message):
                batch = self.micro_batcher.get_batch()
                asyncio.create_task(self._process_batch(batch))
            
            return True
        except queue.Full:
            logger.warning("Message queue full, dropping message")
            self.metrics.total_messages_failed += 1
            return False
    
    async def _process_batch(self, batch: List[StreamMessage]):
        """Process a micro-batch of messages"""
        if not batch:
            return
        
        processing_times = []
        
        for message in batch:
            start_time = time.time()
            
            # Route to appropriate processor
            for processor_name, processor in self.processors.items():
                success, result = await processor.process_message(message)
                
                if success:
                    self.metrics.total_messages_processed += 1
                else:
                    self.metrics.total_messages_failed += 1
            
            elapsed_ms = (time.time() - start_time) * 1000
            processing_times.append(elapsed_ms)
        
        # Update latency metrics
        if processing_times:
            processing_times.sort()
            n = len(processing_times)
            self.metrics.latency_p50_ms = processing_times[int(n * 0.5)]
            self.metrics.latency_p95_ms = processing_times[int(n * 0.95)]
            self.metrics.latency_p99_ms = processing_times[int(n * 0.99)]
    
    async def start(self):
        """Start the streaming pipeline"""
        with self._lock:
            if self.status == StreamStatus.RUNNING:
                logger.warning("Pipeline already running")
                return
            
            self.status = StreamStatus.RUNNING
            self._running = True
            self._start_time = datetime.now()
            
            logger.info("Streaming pipeline started")
            
            # Periodic rebalancing
            asyncio.create_task(self._periodic_rebalance())
            # Periodic metrics reporting
            asyncio.create_task(self._periodic_metrics_reporting())
    
    async def stop(self):
        """Stop the streaming pipeline"""
        with self._lock:
            self.status = StreamStatus.STOPPED
            self._running = False
        
        logger.info("Streaming pipeline stopped")
    
    async def _periodic_rebalance(self):
        """Periodically rebalance partitions"""
        while self._running:
            await asyncio.sleep(30)  # Rebalance every 30 seconds
            self.partition_manager.rebalance_partitions()
    
    async def _periodic_metrics_reporting(self):
        """Periodically report metrics"""
        while self._running:
            await asyncio.sleep(10)  # Report every 10 seconds
            
            # Calculate throughput
            elapsed = (datetime.now() - self._start_time).total_seconds()
            if elapsed > 0:
                self.metrics.throughput_msg_per_sec = (
                    self.metrics.total_messages_processed / elapsed
                )
            
            logger.info(f"Pipeline metrics: {self.get_metrics()}")
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get pipeline metrics"""
        with self._lock:
            elapsed = (datetime.now() - self._start_time).total_seconds()
            
            return {
                'status': self.status.value,
                'total_ingested': self.metrics.total_messages_ingested,
                'total_processed': self.metrics.total_messages_processed,
                'total_failed': self.metrics.total_messages_failed,
                'success_rate': (
                    self.metrics.total_messages_processed / 
                    max(1, self.metrics.total_messages_ingested) * 100
                ),
                'latency_p50_ms': self.metrics.latency_p50_ms,
                'latency_p95_ms': self.metrics.latency_p95_ms,
                'latency_p99_ms': self.metrics.latency_p99_ms,
                'throughput_msg_per_sec': self.metrics.throughput_msg_per_sec,
                'runtime_seconds': elapsed,
                'num_processors': len(self.processors),
                'partition_stats': self.partition_manager.get_partition_stats(),
                'batch_metrics': self.micro_batcher.get_metrics(),
                'processor_metrics': {
                    name: proc.get_metrics() 
                    for name, proc in self.processors.items()
                }
            }
    
    def get_partition_lag(self) -> Dict[int, int]:
        """Get lag for each partition"""
        lag = {}
        for pid, partition in self.partition_manager.partitions.items():
            lag[pid] = partition.offset - partition.committed_offset
        return lag


# Global instance
_streaming_pipeline: Optional[DistributedStreamingPipeline] = None


def get_streaming_pipeline() -> DistributedStreamingPipeline:
    """Get or create global streaming pipeline"""
    global _streaming_pipeline
    if _streaming_pipeline is None:
        _streaming_pipeline = DistributedStreamingPipeline()
    return _streaming_pipeline


async def example_processor_handler(message: StreamMessage) -> Dict[str, Any]:
    """Example processor handler"""
    return {
        'processed': True,
        'message_id': message.message_id,
        'processing_time': datetime.now().isoformat()
    }


if __name__ == "__main__":
    pipeline = get_streaming_pipeline()
    logger.info("Distributed Streaming Pipeline initialized")
