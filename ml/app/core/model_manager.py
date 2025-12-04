#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Advanced model management system for the SecurityAI ML Service.

This module provides:
- Model caching and lifecycle management
- Performance optimization
- Real-time model updates
- Model versioning and A/B testing
- Resource management
- Batch processing optimization
"""

import os
import time
import asyncio
import threading
from typing import Dict, Any, Optional, List, Tuple, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import OrderedDict, defaultdict
import hashlib
import pickle
import numpy as np
import pandas as pd
from loguru import logger
import psutil
from threading import RLock

from .config import settings, ModelType, MODEL_CONFIGS
from .exceptions import (
    ModelError, ModelNotFoundError, ModelLoadError, PredictionError,
    ResourceExhaustionError, error_handler, create_error_context,
    retry_with_backoff, CircuitBreaker
)
from .monitoring import metrics_collector
from ..models.threat_detection import ThreatDetectionModel
from ..models.vulnerability_assessment import VulnerabilityAssessmentModel


@dataclass
class ModelMetadata:
    """Metadata for a loaded model."""
    name: str
    version: str
    model_type: ModelType
    load_time: datetime
    last_used: datetime
    usage_count: int = 0
    memory_usage_mb: float = 0.0
    avg_prediction_time_ms: float = 0.0
    accuracy: Optional[float] = None
    file_path: Optional[str] = None
    checksum: Optional[str] = None


@dataclass
class PredictionRequest:
    """A prediction request with metadata."""
    request_id: str
    model_name: str
    features: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.now)
    priority: int = 1  # 1=high, 2=medium, 3=low
    timeout: float = 30.0


@dataclass
class PredictionResult:
    """Result of a prediction request."""
    request_id: str
    prediction: Any
    confidence: Optional[float] = None
    processing_time_ms: float = 0.0
    model_version: str = "unknown"
    timestamp: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ModelCache:
    """LRU cache for loaded models with memory management."""
    
    def __init__(self, max_size: int = 10, max_memory_mb: float = 2048):
        self.max_size = max_size
        self.max_memory_mb = max_memory_mb
        self._cache = OrderedDict()
        self._metadata = {}
        self._lock = RLock()
        
    def get(self, key: str) -> Optional[Any]:
        """Get a model from cache."""
        with self._lock:
            if key in self._cache:
                # Move to end (most recently used)
                model = self._cache.pop(key)
                self._cache[key] = model
                
                # Update metadata
                if key in self._metadata:
                    self._metadata[key].last_used = datetime.now()
                    self._metadata[key].usage_count += 1
                    
                return model
            return None
            
    def put(self, key: str, model: Any, metadata: ModelMetadata) -> None:
        """Put a model in cache with eviction if necessary."""
        with self._lock:
            # Remove if already exists
            if key in self._cache:
                del self._cache[key]
                
            # Add new model
            self._cache[key] = model
            self._metadata[key] = metadata
            
            # Evict if necessary
            self._evict_if_necessary()
            
    def remove(self, key: str) -> bool:
        """Remove a model from cache."""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                if key in self._metadata:
                    del self._metadata[key]
                return True
            return False
            
    def clear(self) -> None:
        """Clear all models from cache."""
        with self._lock:
            self._cache.clear()
            self._metadata.clear()
            
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._lock:
            total_memory = sum(meta.memory_usage_mb for meta in self._metadata.values())
            
            return {
                "size": len(self._cache),
                "max_size": self.max_size,
                "memory_usage_mb": total_memory,
                "max_memory_mb": self.max_memory_mb,
                "hit_rate": self._calculate_hit_rate(),
                "models": {
                    key: {
                        "usage_count": meta.usage_count,
                        "last_used": meta.last_used.isoformat(),
                        "memory_mb": meta.memory_usage_mb
                    }
                    for key, meta in self._metadata.items()
                }
            }
            
    def _evict_if_necessary(self) -> None:
        """Evict models if cache limits are exceeded."""
        # Evict by size
        while len(self._cache) > self.max_size:
            oldest_key = next(iter(self._cache))
            logger.info(f"Evicting model {oldest_key} due to size limit")
            del self._cache[oldest_key]
            if oldest_key in self._metadata:
                del self._metadata[oldest_key]
                
        # Evict by memory
        total_memory = sum(meta.memory_usage_mb for meta in self._metadata.values())
        while total_memory > self.max_memory_mb and self._cache:
            # Evict least recently used
            oldest_key = next(iter(self._cache))
            logger.info(f"Evicting model {oldest_key} due to memory limit")
            total_memory -= self._metadata.get(oldest_key, ModelMetadata("", "", ModelType.THREAT_DETECTION, datetime.now(), datetime.now())).memory_usage_mb
            del self._cache[oldest_key]
            if oldest_key in self._metadata:
                del self._metadata[oldest_key]
                
    def _calculate_hit_rate(self) -> float:
        """Calculate cache hit rate."""
        total_requests = sum(meta.usage_count for meta in self._metadata.values())
        if total_requests == 0:
            return 0.0
        return len(self._metadata) / total_requests


class ModelManager:
    """Advanced model management system."""
    
    def __init__(self):
        self.cache = ModelCache(
            max_size=settings.model_cache_size,
            max_memory_mb=1024  # 1GB default
        )
        self.executor = ThreadPoolExecutor(max_workers=4)
        self._model_factories = {
            ModelType.THREAT_DETECTION: ThreatDetectionModel,
            ModelType.VULNERABILITY_ASSESSMENT: VulnerabilityAssessmentModel
        }
        self._circuit_breakers = {}
        self._prediction_queue = asyncio.Queue(maxsize=1000)
        self._batch_processor = None
        self._performance_tracker = defaultdict(list)
        self._lock = RLock()
        
        # Initialize circuit breakers
        for model_type in ModelType:
            self._circuit_breakers[model_type.value] = CircuitBreaker(
                failure_threshold=5,
                recovery_timeout=60
            )
            
    async def start_batch_processor(self):
        """Start the batch prediction processor."""
        if self._batch_processor is None:
            self._batch_processor = asyncio.create_task(self._process_prediction_queue())
            logger.info("Batch processor started")
            
    async def stop_batch_processor(self):
        """Stop the batch prediction processor."""
        if self._batch_processor:
            self._batch_processor.cancel()
            try:
                await self._batch_processor
            except asyncio.CancelledError:
                pass
            self._batch_processor = None
            logger.info("Batch processor stopped")
            
    @retry_with_backoff(max_retries=3, exceptions=(ModelLoadError,))
    async def load_model(
        self,
        model_name: str,
        model_version: str = "latest",
        force_reload: bool = False
    ) -> Any:
        """Load a model with caching and error handling."""
        cache_key = f"{model_name}:{model_version}"
        
        # Check cache first
        if not force_reload:
            cached_model = self.cache.get(cache_key)
            if cached_model is not None:
                logger.debug(f"Model {cache_key} loaded from cache")
                return cached_model
                
        # Load model with monitoring
        with metrics_collector.track_model_loading(model_name):
            try:
                model = await self._load_model_from_storage(model_name, model_version)
                
                # Calculate memory usage
                memory_usage = self._estimate_model_memory(model)
                
                # Create metadata
                metadata = ModelMetadata(
                    name=model_name,
                    version=model_version,
                    model_type=ModelType(model_name),
                    load_time=datetime.now(),
                    last_used=datetime.now(),
                    memory_usage_mb=memory_usage
                )
                
                # Cache the model
                self.cache.put(cache_key, model, metadata)
                
                logger.info(f"Model {cache_key} loaded successfully (Memory: {memory_usage:.1f}MB)")
                return model
                
            except Exception as e:
                error_context = create_error_context(
                    model_name=model_name,
                    endpoint="load_model"
                )
                raise ModelLoadError(
                    model_name=model_name,
                    reason=str(e),
                    context=error_context
                )
                
    async def _load_model_from_storage(
        self,
        model_name: str,
        model_version: str
    ) -> Any:
        """Load model from storage (file system, S3, etc.)."""
        import importlib
        from app.core.adapters import ADAPTER_MAP
        
        model_type = ModelType(model_name)
        config = MODEL_CONFIGS.get(model_type)
        
        if not config:
            raise ModelNotFoundError(f"Configuration not found for {model_name}")
            
        try:
            # Dynamic import of production module
            module_path = config.get("module_path")
            factory_func_name = config.get("factory_func")
            
            if module_path and factory_func_name:
                # Import module
                module = importlib.import_module(module_path)
                
                # Get factory function
                factory = getattr(module, factory_func_name)
                
                # Create model instance
                # Some factories might be async, handle if needed (assuming sync for now based on code)
                if asyncio.iscoroutinefunction(factory):
                    model_instance = await factory()
                else:
                    model_instance = factory()
                    
                # Wrap in adapter
                adapter_class = ADAPTER_MAP.get(model_type)
                if adapter_class:
                    return adapter_class(model_instance)
                else:
                    logger.warning(f"No adapter found for {model_name}, returning raw instance")
                    return model_instance
            
            # Fallback for legacy models (VulnerabilityAssessment)
            elif model_type == ModelType.VULNERABILITY_ASSESSMENT:
                from app.models.vulnerability_assessment import VulnerabilityAssessmentModel
                model_instance = VulnerabilityAssessmentModel()
                adapter_class = ADAPTER_MAP.get(model_type)
                return adapter_class(model_instance)
                
            else:
                raise ModelNotFoundError(f"Invalid configuration for {model_name}")
                
        except ImportError as e:
            logger.error(f"Failed to import module for {model_name}: {e}")
            raise ModelLoadError(model_name, f"Import failed: {e}")
        except Exception as e:
            logger.error(f"Failed to load model {model_name}: {e}")
            raise ModelLoadError(model_name, str(e))
        
    def _estimate_model_memory(self, model: Any) -> float:
        """Estimate model memory usage in MB."""
        try:
            # Simple estimation based on pickle size
            pickled = pickle.dumps(model)
            return len(pickled) / 1024 / 1024
        except Exception:
            # Fallback estimation
            return 50.0  # Default 50MB
            
    async def predict(
        self,
        model_name: str,
        features: Dict[str, Any],
        model_version: str = "latest",
        request_id: str = None
    ) -> PredictionResult:
        """Make a single prediction with comprehensive error handling."""
        start_time = time.time()
        request_id = request_id or self._generate_request_id()
        
        try:
            # Check circuit breaker
            circuit_breaker = self._circuit_breakers.get(model_name)
            if circuit_breaker and circuit_breaker.state == "open":
                raise PredictionError(
                    model_name=model_name,
                    reason="Circuit breaker is open"
                )
                
            # Load model
            model = await self.load_model(model_name, model_version)
            
            # Make prediction with monitoring
            with metrics_collector.track_prediction(model_name):
                prediction_start = time.time()
                
                # Use adapter interface
                if hasattr(model, 'predict'):
                    # Adapters return a dict with prediction details
                    result_data = await model.predict(features)
                    
                    # Extract standard fields if present, or use whole result
                    if isinstance(result_data, dict):
                        prediction = result_data.get("prediction", result_data)
                        confidence = result_data.get("confidence")
                    else:
                        prediction = result_data
                        confidence = None
                else:
                    raise PredictionError(
                        model_name=model_name,
                        reason="Model does not support prediction"
                    )
                    
                prediction_time = (time.time() - prediction_start) * 1000
                
            # Update performance tracking
            self._update_performance_metrics(model_name, prediction_time)
            
            # Create result
            result = PredictionResult(
                request_id=request_id,
                prediction=prediction,
                confidence=confidence,
                processing_time_ms=(time.time() - start_time) * 1000,
                model_version=model_version,
                metadata={
                    "model_name": model_name,
                    "features_count": len(features)
                }
            )
            
            logger.debug(f"Prediction completed for {model_name} in {result.processing_time_ms:.1f}ms")
            return result
            
        except Exception as e:
            processing_time = (time.time() - start_time) * 1000
            
            # Handle with error handler
            error_context = create_error_context(
                request_id=request_id,
                model_name=model_name,
                endpoint="predict"
            )
            
            if isinstance(e, PredictionError):
                e.context = error_context
            else:
                e = PredictionError(
                    model_name=model_name,
                    reason=str(e),
                    context=error_context
                )
                
            # Try error recovery
            try:
                recovery_result = error_handler.handle_error(e, error_context)
                if recovery_result:
                    return PredictionResult(
                        request_id=request_id,
                        prediction=recovery_result.get("prediction", "unknown"),
                        confidence=recovery_result.get("confidence", 0.0),
                        processing_time_ms=processing_time,
                        model_version=model_version,
                        metadata={"fallback": True, "error": str(e)}
                    )
            except Exception:
                pass
                
            raise e
            
    async def batch_predict(
        self,
        requests: List[PredictionRequest]
    ) -> List[PredictionResult]:
        """Process multiple predictions efficiently."""
        if len(requests) > settings.batch_size_limit:
            raise ResourceExhaustionError(
                resource_type=f"batch_size (limit: {settings.batch_size_limit})"
            )
            
        # Group requests by model for efficiency
        model_groups = defaultdict(list)
        for req in requests:
            model_groups[req.model_name].append(req)
            
        results = []
        
        # Process each model group
        for model_name, model_requests in model_groups.items():
            try:
                # Load model once for all requests
                model = await self.load_model(model_name)
                
                # Process requests in parallel
                tasks = [
                    self._process_single_request(model, req)
                    for req in model_requests
                ]
                
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for result in batch_results:
                    if isinstance(result, Exception):
                        # Create error result
                        error_result = PredictionResult(
                            request_id="unknown",
                            prediction="error",
                            confidence=0.0,
                            metadata={"error": str(result)}
                        )
                        results.append(error_result)
                    else:
                        results.append(result)
                        
            except Exception as e:
                # Create error results for all requests in this group
                for req in model_requests:
                    error_result = PredictionResult(
                        request_id=req.request_id,
                        prediction="error",
                        confidence=0.0,
                        metadata={"error": str(e)}
                    )
                    results.append(error_result)
                    
        return results
        
    async def _process_single_request(
        self,
        model: Any,
        request: PredictionRequest
    ) -> PredictionResult:
        """Process a single prediction request."""
        start_time = time.time()
        
        try:
            with metrics_collector.track_prediction(request.model_name):
                if request.model_name == ModelType.THREAT_DETECTION.value:
                    prediction, confidence = model.predict(request.features)
                elif request.model_name == ModelType.VULNERABILITY_ASSESSMENT.value:
                    score, severity = model.predict(request.features)
                    prediction = severity
                    confidence = score / 10.0
                else:
                    prediction = model.predict(request.features)
                    confidence = None
                    
            return PredictionResult(
                request_id=request.request_id,
                prediction=prediction,
                confidence=confidence,
                processing_time_ms=(time.time() - start_time) * 1000
            )
            
        except Exception as e:
            raise PredictionError(
                model_name=request.model_name,
                reason=str(e)
            )
            
    async def _process_prediction_queue(self):
        """Process queued predictions in batches."""
        batch = []
        batch_timeout = 0.1  # 100ms batch timeout
        
        while True:
            try:
                # Collect requests for batch
                try:
                    request = await asyncio.wait_for(
                        self._prediction_queue.get(),
                        timeout=batch_timeout
                    )
                    batch.append(request)
                    
                    # Collect more requests up to batch size
                    while len(batch) < 32 and not self._prediction_queue.empty():
                        try:
                            request = self._prediction_queue.get_nowait()
                            batch.append(request)
                        except asyncio.QueueEmpty:
                            break
                            
                except asyncio.TimeoutError:
                    if not batch:
                        continue
                        
                # Process batch if we have requests
                if batch:
                    await self.batch_predict(batch)
                    batch.clear()
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in batch processor: {e}")
                batch.clear()
                
    def _update_performance_metrics(self, model_name: str, prediction_time_ms: float):
        """Update performance tracking metrics."""
        with self._lock:
            self._performance_tracker[model_name].append(prediction_time_ms)
            
            # Keep only recent measurements (last 1000)
            if len(self._performance_tracker[model_name]) > 1000:
                self._performance_tracker[model_name] = self._performance_tracker[model_name][-1000:]
                
    def _generate_request_id(self) -> str:
        """Generate a unique request ID."""
        return hashlib.md5(f"{time.time()}_{threading.current_thread().ident}".encode()).hexdigest()[:16]
        
    def get_model_stats(self) -> Dict[str, Any]:
        """Get comprehensive model statistics."""
        with self._lock:
            stats = {
                "cache": self.cache.get_stats(),
                "performance": {},
                "circuit_breakers": {},
                "system": {
                    "memory_usage_mb": psutil.virtual_memory().used / 1024 / 1024,
                    "cpu_percent": psutil.cpu_percent()
                }
            }
            
            # Performance stats
            for model_name, times in self._performance_tracker.items():
                if times:
                    stats["performance"][model_name] = {
                        "avg_prediction_time_ms": sum(times) / len(times),
                        "min_prediction_time_ms": min(times),
                        "max_prediction_time_ms": max(times),
                        "total_predictions": len(times)
                    }
                    
            # Circuit breaker stats
            for name, cb in self._circuit_breakers.items():
                stats["circuit_breakers"][name] = {
                    "state": cb.state,
                    "failure_count": cb.failure_count,
                    "last_failure_time": cb.last_failure_time
                }
                
            return stats
            
    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "checks": {}
        }
        
        # Check model cache
        cache_stats = self.cache.get_stats()
        health_status["checks"]["model_cache"] = {
            "status": "healthy" if cache_stats["memory_usage_mb"] < cache_stats["max_memory_mb"] else "warning",
            "details": cache_stats
        }
        
        # Check system resources
        memory_percent = psutil.virtual_memory().percent
        health_status["checks"]["system_memory"] = {
            "status": "healthy" if memory_percent < 80 else "warning" if memory_percent < 95 else "critical",
            "usage_percent": memory_percent
        }
        
        # Check circuit breakers
        open_breakers = [name for name, cb in self._circuit_breakers.items() if cb.state == "open"]
        health_status["checks"]["circuit_breakers"] = {
            "status": "healthy" if not open_breakers else "warning",
            "open_breakers": open_breakers
        }
        
        # Overall status
        if any(check["status"] == "critical" for check in health_status["checks"].values()):
            health_status["status"] = "critical"
        elif any(check["status"] == "warning" for check in health_status["checks"].values()):
            health_status["status"] = "warning"
            
        return health_status


# Global model manager instance
model_manager = ModelManager()