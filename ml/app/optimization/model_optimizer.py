"""Advanced model optimization for improved performance and efficiency."""

import asyncio
import time
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor
import numpy as np
import torch
import torch.nn as nn
from torch.quantization import quantize_dynamic
from sklearn.base import BaseEstimator
import joblib
from functools import lru_cache, wraps
import threading
from collections import defaultdict, deque
from datetime import datetime, timedelta

from ..core.config import settings
from ..core.logging_system import get_logger
from ..core.monitoring import metrics_collector
from ..core.exceptions import ModelError, SecurityAIException


logger = get_logger(__name__)


@dataclass
class OptimizationConfig:
    """Configuration for model optimization."""
    enable_quantization: bool = True
    enable_batch_processing: bool = True
    enable_model_caching: bool = True
    enable_feature_caching: bool = True
    max_batch_size: int = 32
    batch_timeout_ms: int = 100
    cache_ttl_seconds: int = 300
    quantization_backend: str = "fbgemm"  # or "qnnpack" for mobile
    optimization_level: str = "balanced"  # "speed", "balanced", "accuracy"
    enable_gpu_acceleration: bool = True
    enable_parallel_inference: bool = True
    max_workers: int = 4


class ModelQuantizer:
    """Handles model quantization for improved inference speed."""
    
    def __init__(self, config: OptimizationConfig):
        self.config = config
        self.quantized_models = {}
        
    def quantize_pytorch_model(self, model: nn.Module, model_name: str) -> nn.Module:
        """Quantize a PyTorch model for faster inference."""
        try:
            if not self.config.enable_quantization:
                return model
                
            logger.info(f"Quantizing PyTorch model: {model_name}")
            
            # Set model to evaluation mode
            model.eval()
            
            # Dynamic quantization
            quantized_model = quantize_dynamic(
                model,
                {nn.Linear, nn.Conv2d, nn.LSTM, nn.GRU},
                dtype=torch.qint8,
                inplace=False
            )
            
            self.quantized_models[model_name] = quantized_model
            
            # Measure size reduction
            original_size = sum(p.numel() * p.element_size() for p in model.parameters())
            quantized_size = sum(p.numel() * p.element_size() for p in quantized_model.parameters())
            
            size_reduction = (1 - quantized_size / original_size) * 100
            
            logger.info(
                f"Model {model_name} quantized successfully",
                original_size_mb=original_size / (1024 * 1024),
                quantized_size_mb=quantized_size / (1024 * 1024),
                size_reduction_percent=size_reduction
            )
            
            metrics_collector.record_model_optimization(
                model_name, "quantization", size_reduction
            )
            
            return quantized_model
            
        except Exception as e:
            logger.error(f"Failed to quantize model {model_name}: {str(e)}", error=e)
            return model  # Return original model if quantization fails
    
    def optimize_sklearn_model(self, model: BaseEstimator, model_name: str) -> BaseEstimator:
        """Optimize scikit-learn models for faster inference."""
        try:
            # For tree-based models, we can optimize by reducing precision
            if hasattr(model, 'tree_'):
                # Already optimized during training
                pass
            
            logger.info(f"Sklearn model {model_name} optimization completed")
            return model
            
        except Exception as e:
            logger.error(f"Failed to optimize sklearn model {model_name}: {str(e)}", error=e)
            return model


class BatchProcessor:
    """Handles batch processing for improved throughput."""
    
    def __init__(self, config: OptimizationConfig):
        self.config = config
        self.batch_queues = defaultdict(list)
        self.batch_futures = defaultdict(list)
        self.batch_locks = defaultdict(threading.Lock)
        self.batch_timers = {}
        
    async def add_to_batch(self, model_name: str, input_data: Any, future: asyncio.Future):
        """Add input to batch queue for processing."""
        if not self.config.enable_batch_processing:
            # Process immediately if batching is disabled
            return await self._process_single(model_name, input_data, future)
        
        with self.batch_locks[model_name]:
            self.batch_queues[model_name].append(input_data)
            self.batch_futures[model_name].append(future)
            
            # Start timer for this batch if not already started
            if model_name not in self.batch_timers:
                self.batch_timers[model_name] = asyncio.create_task(
                    self._batch_timeout(model_name)
                )
            
            # Process batch if it's full
            if len(self.batch_queues[model_name]) >= self.config.max_batch_size:
                await self._process_batch(model_name)
    
    async def _batch_timeout(self, model_name: str):
        """Process batch after timeout."""
        await asyncio.sleep(self.config.batch_timeout_ms / 1000)
        
        with self.batch_locks[model_name]:
            if self.batch_queues[model_name]:
                await self._process_batch(model_name)
    
    async def _process_batch(self, model_name: str):
        """Process a batch of inputs."""
        if not self.batch_queues[model_name]:
            return
        
        batch_inputs = self.batch_queues[model_name].copy()
        batch_futures = self.batch_futures[model_name].copy()
        
        # Clear the queues
        self.batch_queues[model_name].clear()
        self.batch_futures[model_name].clear()
        
        # Cancel timer
        if model_name in self.batch_timers:
            self.batch_timers[model_name].cancel()
            del self.batch_timers[model_name]
        
        try:
            # Process batch (this would be implemented by the specific model)
            results = await self._execute_batch_inference(model_name, batch_inputs)
            
            # Set results for all futures
            for future, result in zip(batch_futures, results):
                if not future.done():
                    future.set_result(result)
                    
        except Exception as e:
            # Set exception for all futures
            for future in batch_futures:
                if not future.done():
                    future.set_exception(e)
    
    async def _execute_batch_inference(self, model_name: str, batch_inputs: List[Any]) -> List[Any]:
        """Execute batch inference (to be implemented by specific models)."""
        # This is a placeholder - actual implementation would depend on the model type
        logger.info(f"Processing batch of {len(batch_inputs)} inputs for {model_name}")
        
        # Simulate batch processing
        results = []
        for input_data in batch_inputs:
            # This would call the actual model inference
            result = await self._process_single_input(model_name, input_data)
            results.append(result)
        
        return results
    
    async def _process_single_input(self, model_name: str, input_data: Any) -> Any:
        """Process a single input (placeholder)."""
        # This would be implemented by the specific model
        return {"prediction": "placeholder", "confidence": 0.5}
    
    async def _process_single(self, model_name: str, input_data: Any, future: asyncio.Future):
        """Process single input immediately."""
        try:
            result = await self._process_single_input(model_name, input_data)
            future.set_result(result)
        except Exception as e:
            future.set_exception(e)


class FeatureCache:
    """Caches processed features to avoid recomputation."""
    
    def __init__(self, config: OptimizationConfig):
        self.config = config
        self.cache = {}
        self.cache_timestamps = {}
        self.cache_lock = threading.Lock()
        
    def get_cache_key(self, raw_data: Any) -> str:
        """Generate cache key for raw data."""
        if isinstance(raw_data, dict):
            # Sort keys for consistent hashing
            sorted_items = sorted(raw_data.items())
            return str(hash(str(sorted_items)))
        elif isinstance(raw_data, (list, tuple)):
            return str(hash(str(raw_data)))
        else:
            return str(hash(str(raw_data)))
    
    def get(self, cache_key: str) -> Optional[Any]:
        """Get cached features if available and not expired."""
        if not self.config.enable_feature_caching:
            return None
            
        with self.cache_lock:
            if cache_key in self.cache:
                timestamp = self.cache_timestamps[cache_key]
                if datetime.now() - timestamp < timedelta(seconds=self.config.cache_ttl_seconds):
                    metrics_collector.increment_counter("feature_cache_hits")
                    return self.cache[cache_key]
                else:
                    # Remove expired entry
                    del self.cache[cache_key]
                    del self.cache_timestamps[cache_key]
            
            metrics_collector.increment_counter("feature_cache_misses")
            return None
    
    def set(self, cache_key: str, features: Any):
        """Cache processed features."""
        if not self.config.enable_feature_caching:
            return
            
        with self.cache_lock:
            self.cache[cache_key] = features
            self.cache_timestamps[cache_key] = datetime.now()
            
            # Clean up old entries if cache is getting too large
            if len(self.cache) > 1000:
                self._cleanup_cache()
    
    def _cleanup_cache(self):
        """Remove expired entries from cache."""
        current_time = datetime.now()
        expired_keys = []
        
        for key, timestamp in self.cache_timestamps.items():
            if current_time - timestamp >= timedelta(seconds=self.config.cache_ttl_seconds):
                expired_keys.append(key)
        
        for key in expired_keys:
            del self.cache[key]
            del self.cache_timestamps[key]
        
        logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")


class ModelOptimizer:
    """Main model optimization coordinator."""
    
    def __init__(self, config: Optional[OptimizationConfig] = None):
        self.config = config or OptimizationConfig()
        self.quantizer = ModelQuantizer(self.config)
        self.batch_processor = BatchProcessor(self.config)
        self.feature_cache = FeatureCache(self.config)
        self.executor = ThreadPoolExecutor(max_workers=self.config.max_workers)
        self.optimized_models = {}
        self.performance_stats = defaultdict(list)
        
    def optimize_model(self, model: Union[nn.Module, BaseEstimator], model_name: str) -> Union[nn.Module, BaseEstimator]:
        """Optimize a model for better performance."""
        try:
            logger.info(f"Starting optimization for model: {model_name}")
            
            if isinstance(model, nn.Module):
                optimized_model = self.quantizer.quantize_pytorch_model(model, model_name)
            elif isinstance(model, BaseEstimator):
                optimized_model = self.quantizer.optimize_sklearn_model(model, model_name)
            else:
                logger.warning(f"Unknown model type for {model_name}, skipping optimization")
                optimized_model = model
            
            self.optimized_models[model_name] = optimized_model
            
            logger.info(f"Model {model_name} optimization completed")
            return optimized_model
            
        except Exception as e:
            logger.error(f"Failed to optimize model {model_name}: {str(e)}", error=e)
            return model
    
    async def predict_optimized(self, model_name: str, input_data: Any, 
                              preprocess_func: Optional[callable] = None) -> Any:
        """Make optimized prediction with caching and batching."""
        start_time = time.time()
        
        try:
            # Check feature cache first
            cache_key = self.feature_cache.get_cache_key(input_data)
            cached_features = self.feature_cache.get(cache_key)
            
            if cached_features is not None:
                processed_features = cached_features
                logger.debug(f"Using cached features for {model_name}")
            else:
                # Preprocess features
                if preprocess_func:
                    processed_features = await self._run_in_executor(preprocess_func, input_data)
                else:
                    processed_features = input_data
                
                # Cache the processed features
                self.feature_cache.set(cache_key, processed_features)
            
            # Create future for batch processing
            future = asyncio.Future()
            
            # Add to batch queue
            await self.batch_processor.add_to_batch(model_name, processed_features, future)
            
            # Wait for result
            result = await future
            
            # Record performance metrics
            processing_time = (time.time() - start_time) * 1000
            self.performance_stats[model_name].append(processing_time)
            
            metrics_collector.record_model_performance(
                model_name, processing_time, "optimized_prediction"
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Optimized prediction failed for {model_name}: {str(e)}", error=e)
            raise ModelError(f"Prediction failed: {str(e)}")
    
    async def _run_in_executor(self, func: callable, *args) -> Any:
        """Run function in thread executor for CPU-bound tasks."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, func, *args)
    
    def get_performance_stats(self, model_name: str) -> Dict[str, Any]:
        """Get performance statistics for a model."""
        stats = self.performance_stats.get(model_name, [])
        
        if not stats:
            return {"message": "No performance data available"}
        
        recent_stats = stats[-100:]  # Last 100 predictions
        
        return {
            "model_name": model_name,
            "total_predictions": len(stats),
            "avg_processing_time_ms": np.mean(recent_stats),
            "min_processing_time_ms": np.min(recent_stats),
            "max_processing_time_ms": np.max(recent_stats),
            "p95_processing_time_ms": np.percentile(recent_stats, 95),
            "p99_processing_time_ms": np.percentile(recent_stats, 99),
            "cache_hit_rate": self._calculate_cache_hit_rate(),
            "optimization_enabled": {
                "quantization": self.config.enable_quantization,
                "batch_processing": self.config.enable_batch_processing,
                "feature_caching": self.config.enable_feature_caching,
                "parallel_inference": self.config.enable_parallel_inference
            }
        }
    
    def _calculate_cache_hit_rate(self) -> float:
        """Calculate feature cache hit rate."""
        try:
            hits = metrics_collector.get_counter_value("feature_cache_hits")
            misses = metrics_collector.get_counter_value("feature_cache_misses")
            total = hits + misses
            return (hits / total * 100) if total > 0 else 0.0
        except:
            return 0.0
    
    def cleanup(self):
        """Cleanup resources."""
        self.executor.shutdown(wait=True)
        logger.info("Model optimizer cleanup completed")


# Global optimizer instance
model_optimizer = ModelOptimizer()


def optimize_model_for_production(model: Union[nn.Module, BaseEstimator], 
                                model_name: str) -> Union[nn.Module, BaseEstimator]:
    """Convenience function to optimize a model for production use."""
    return model_optimizer.optimize_model(model, model_name)


async def predict_with_optimization(model_name: str, input_data: Any, 
                                  preprocess_func: Optional[callable] = None) -> Any:
    """Convenience function for optimized prediction."""
    return await model_optimizer.predict_optimized(model_name, input_data, preprocess_func)


def get_optimization_stats(model_name: str) -> Dict[str, Any]:
    """Get optimization performance statistics."""
    return model_optimizer.get_performance_stats(model_name)