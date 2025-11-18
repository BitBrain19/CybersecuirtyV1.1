"""ML Service Integration Module

This module provides a unified interface for all ML components,
integrating threat detection, vulnerability assessment, streaming,
batch processing, monitoring, versioning, and A/B testing.
"""

import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass
from enum import Enum
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models.threat_detection import get_threat_detector
from ..models.vulnerability_assessment import get_vulnerability_assessor
from ..streaming.stream_processor import get_stream_processor
from ..streaming.websocket_server import get_websocket_server
from ..batch.batch_processor import get_batch_processor, BatchConfig
from ..monitoring.model_health import get_model_health_monitor
from ..monitoring.auto_retrain import get_auto_retrainer
from ..versioning.model_versioning import get_model_registry, get_ab_test_manager
from ..benchmarking.performance_benchmark import get_model_benchmark
from ..core.error_handler import get_error_manager, with_error_recovery, RecoveryStrategy, RecoveryAction
from ..core.exceptions import MLServiceError
from ..core.config import get_config

logger = logging.getLogger(__name__)

class ServiceStatus(Enum):
    """ML service status."""
    INITIALIZING = "initializing"
    RUNNING = "running"
    DEGRADED = "degraded"
    STOPPED = "stopped"
    ERROR = "error"

class PredictionMode(Enum):
    """Prediction execution modes."""
    SYNC = "sync"
    ASYNC = "async"
    BATCH = "batch"
    STREAM = "stream"

@dataclass
class ServiceHealth:
    """Service health status."""
    status: ServiceStatus
    timestamp: datetime
    components: Dict[str, bool]
    metrics: Dict[str, Any]
    errors: List[str]
    uptime_seconds: float

@dataclass
class PredictionRequest:
    """Unified prediction request."""
    request_id: str
    model_type: str  # 'threat_detection' or 'vulnerability_assessment'
    data: Dict[str, Any]
    mode: PredictionMode = PredictionMode.SYNC
    user_id: Optional[str] = None
    ab_test_id: Optional[str] = None
    metadata: Dict[str, Any] = None
    timeout_seconds: float = 30.0

@dataclass
class PredictionResponse:
    """Unified prediction response."""
    request_id: str
    model_type: str
    model_version: str
    prediction: Dict[str, Any]
    confidence: float
    latency_ms: float
    timestamp: datetime
    success: bool
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None

class MLService:
    """Unified ML service integrating all components."""
    
    def __init__(self):
        self.config = get_config()
        self.status = ServiceStatus.INITIALIZING
        self.start_time = datetime.now()
        self.service_lock = threading.Lock()
        
        # Component instances
        self.threat_detector = None
        self.vulnerability_assessor = None
        self.stream_processor = None
        self.websocket_server = None
        self.batch_processor = None
        self.health_monitor = None
        self.auto_retrainer = None
        self.model_registry = None
        self.ab_test_manager = None
        self.benchmark = None
        self.error_manager = None
        
        # Thread pool for async operations
        self.executor = ThreadPoolExecutor(max_workers=self.config.get('ml_service_workers', 10))
        
        # Service metrics
        self.metrics = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'avg_latency_ms': 0.0,
            'active_connections': 0,
            'active_batch_jobs': 0,
            'active_ab_tests': 0
        }
        
        logger.info("ML Service initialized")
    
    @with_error_recovery("MLService", RecoveryStrategy(RecoveryAction.RETRY, max_attempts=3))
    def initialize(self) -> bool:
        """Initialize all ML service components."""
        try:
            logger.info("Initializing ML service components...")
            
            # Initialize core components
            self.error_manager = get_error_manager()
            self.model_registry = get_model_registry()
            self.ab_test_manager = get_ab_test_manager(self.model_registry)
            
            # Initialize models
            self.threat_detector = get_threat_detector()
            self.vulnerability_assessor = get_vulnerability_assessor()
            
            # Initialize processing components
            self.stream_processor = get_stream_processor()
            self.websocket_server = get_websocket_server()
            self.batch_processor = get_batch_processor()
            
            # Initialize monitoring
            self.health_monitor = get_model_health_monitor()
            self.auto_retrainer = get_auto_retrainer()
            self.benchmark = get_model_benchmark()
            
            # Register models with stream processor
            self.stream_processor.register_model('threat_detection', self.threat_detector)
            self.stream_processor.register_model('vulnerability_assessment', self.vulnerability_assessor)
            
            # Start monitoring
            self.health_monitor.start_monitoring()
            self.auto_retrainer.start_scheduler()
            
            # Update status
            with self.service_lock:
                self.status = ServiceStatus.RUNNING
            
            logger.info("ML service initialization completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize ML service: {str(e)}")
            with self.service_lock:
                self.status = ServiceStatus.ERROR
            raise MLServiceError(f"Service initialization failed: {str(e)}")
    
    def get_health(self) -> ServiceHealth:
        """Get comprehensive service health status."""
        with self.service_lock:
            current_status = self.status
        
        # Check component health
        components = {
            'threat_detector': self.threat_detector is not None,
            'vulnerability_assessor': self.vulnerability_assessor is not None,
            'stream_processor': self.stream_processor is not None and self.stream_processor.is_running,
            'websocket_server': self.websocket_server is not None,
            'batch_processor': self.batch_processor is not None,
            'health_monitor': self.health_monitor is not None,
            'auto_retrainer': self.auto_retrainer is not None,
            'model_registry': self.model_registry is not None,
            'ab_test_manager': self.ab_test_manager is not None
        }
        
        # Collect errors
        errors = []
        if self.error_manager:
            recent_errors = self.error_manager.get_recent_errors(hours=1)
            errors = [error.message for error in recent_errors[-5:]]  # Last 5 errors
        
        # Calculate uptime
        uptime_seconds = (datetime.now() - self.start_time).total_seconds()
        
        # Update metrics
        if self.stream_processor:
            self.metrics['active_connections'] = len(self.stream_processor.active_connections)
        
        if self.batch_processor:
            self.metrics['active_batch_jobs'] = len(self.batch_processor.active_jobs)
        
        if self.ab_test_manager:
            self.metrics['active_ab_tests'] = len(self.ab_test_manager.list_active_tests())
        
        return ServiceHealth(
            status=current_status,
            timestamp=datetime.now(),
            components=components,
            metrics=self.metrics.copy(),
            errors=errors,
            uptime_seconds=uptime_seconds
        )
    
    @with_error_recovery("MLService", RecoveryStrategy(RecoveryAction.RETRY, max_attempts=2))
    async def predict(self, request: PredictionRequest) -> PredictionResponse:
        """Unified prediction interface supporting multiple modes."""
        start_time = datetime.now()
        
        try:
            # Update metrics
            with self.service_lock:
                self.metrics['total_requests'] += 1
            
            # Determine model version (A/B testing)
            model_version = "default"
            if request.ab_test_id and self.ab_test_manager:
                try:
                    model_version = self.ab_test_manager.get_version_for_request(
                        request.ab_test_id, request.user_id, request.data
                    )
                except Exception as e:
                    logger.warning(f"A/B test version selection failed: {str(e)}")
            
            # Route to appropriate model
            if request.model_type == 'threat_detection':
                if not self.threat_detector:
                    raise MLServiceError("Threat detection model not available")
                
                if request.mode == PredictionMode.ASYNC:
                    prediction = await self._predict_async(self.threat_detector, request.data)
                else:
                    prediction = self.threat_detector.predict(request.data)
                    
            elif request.model_type == 'vulnerability_assessment':
                if not self.vulnerability_assessor:
                    raise MLServiceError("Vulnerability assessment model not available")
                
                if request.mode == PredictionMode.ASYNC:
                    prediction = await self._predict_async(self.vulnerability_assessor, request.data)
                else:
                    prediction = self.vulnerability_assessor.predict(request.data)
                    
            else:
                raise MLServiceError(f"Unknown model type: {request.model_type}")
            
            # Calculate latency
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            # Create response
            response = PredictionResponse(
                request_id=request.request_id,
                model_type=request.model_type,
                model_version=model_version,
                prediction=prediction,
                confidence=prediction.get('confidence', 0.0),
                latency_ms=latency_ms,
                timestamp=datetime.now(),
                success=True,
                metadata=request.metadata
            )
            
            # Record A/B test result
            if request.ab_test_id and self.ab_test_manager:
                try:
                    self.ab_test_manager.record_result(
                        test_id=request.ab_test_id,
                        version_id=model_version,
                        user_id=request.user_id,
                        request_data=request.data,
                        response_data=prediction,
                        latency_ms=latency_ms,
                        success=True,
                        metrics={'confidence': response.confidence}
                    )
                except Exception as e:
                    logger.warning(f"Failed to record A/B test result: {str(e)}")
            
            # Update success metrics
            with self.service_lock:
                self.metrics['successful_requests'] += 1
                # Update rolling average latency
                total_requests = self.metrics['total_requests']
                current_avg = self.metrics['avg_latency_ms']
                self.metrics['avg_latency_ms'] = ((current_avg * (total_requests - 1)) + latency_ms) / total_requests
            
            return response
            
        except Exception as e:
            # Calculate latency even for errors
            latency_ms = (datetime.now() - start_time).total_seconds() * 1000
            
            # Update error metrics
            with self.service_lock:
                self.metrics['failed_requests'] += 1
            
            # Record A/B test error
            if request.ab_test_id and self.ab_test_manager:
                try:
                    self.ab_test_manager.record_result(
                        test_id=request.ab_test_id,
                        version_id=model_version,
                        user_id=request.user_id,
                        request_data=request.data,
                        response_data={},
                        latency_ms=latency_ms,
                        success=False,
                        error_message=str(e)
                    )
                except Exception as ab_error:
                    logger.warning(f"Failed to record A/B test error: {str(ab_error)}")
            
            # Create error response
            response = PredictionResponse(
                request_id=request.request_id,
                model_type=request.model_type,
                model_version=model_version,
                prediction={},
                confidence=0.0,
                latency_ms=latency_ms,
                timestamp=datetime.now(),
                success=False,
                error_message=str(e),
                metadata=request.metadata
            )
            
            logger.error(f"Prediction failed for request {request.request_id}: {str(e)}")
            return response
    
    async def _predict_async(self, model, data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute prediction asynchronously."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self.executor, model.predict, data)
    
    def predict_batch(self, requests: List[PredictionRequest], 
                     config: Optional[BatchConfig] = None) -> List[PredictionResponse]:
        """Process multiple predictions in batch."""
        if not self.batch_processor:
            raise MLServiceError("Batch processor not available")
        
        # Convert requests to batch items
        batch_items = []
        for req in requests:
            batch_items.append({
                'id': req.request_id,
                'model_type': req.model_type,
                'data': req.data,
                'metadata': req.metadata or {}
            })
        
        # Create batch job
        job_id = self.batch_processor.create_job(
            items=batch_items,
            config=config or BatchConfig()
        )
        
        # Process batch
        results = self.batch_processor.process_job(job_id)
        
        # Convert results to responses
        responses = []
        for result in results:
            response = PredictionResponse(
                request_id=result['id'],
                model_type=result['model_type'],
                model_version="batch",
                prediction=result.get('prediction', {}),
                confidence=result.get('confidence', 0.0),
                latency_ms=result.get('processing_time_ms', 0.0),
                timestamp=datetime.now(),
                success=result.get('success', False),
                error_message=result.get('error'),
                metadata=result.get('metadata', {})
            )
            responses.append(response)
        
        return responses
    
    def start_streaming(self, port: int = 8765) -> bool:
        """Start WebSocket streaming server."""
        if not self.websocket_server:
            raise MLServiceError("WebSocket server not available")
        
        try:
            # Start stream processor
            if self.stream_processor and not self.stream_processor.is_running:
                self.stream_processor.start()
            
            # Start WebSocket server
            self.websocket_server.start(port=port)
            
            logger.info(f"Streaming server started on port {port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start streaming server: {str(e)}")
            return False
    
    def stop_streaming(self) -> bool:
        """Stop WebSocket streaming server."""
        try:
            if self.websocket_server:
                self.websocket_server.stop()
            
            if self.stream_processor and self.stream_processor.is_running:
                self.stream_processor.stop()
            
            logger.info("Streaming server stopped")
            return True
            
        except Exception as e:
            logger.error(f"Failed to stop streaming server: {str(e)}")
            return False
    
    def create_ab_test(self, name: str, description: str, control_version: str,
                      treatment_versions: List[str], traffic_split: Dict[str, float],
                      duration_days: int = 14) -> str:
        """Create a new A/B test."""
        if not self.ab_test_manager:
            raise MLServiceError("A/B test manager not available")
        
        return self.ab_test_manager.create_test(
            name=name,
            description=description,
            control_version=control_version,
            treatment_versions=treatment_versions,
            traffic_split=traffic_split,
            duration_days=duration_days
        )
    
    def get_ab_test_summary(self, test_id: str) -> Dict[str, Any]:
        """Get A/B test summary."""
        if not self.ab_test_manager:
            raise MLServiceError("A/B test manager not available")
        
        summary = self.ab_test_manager.get_test_summary(test_id)
        
        return {
            'test_id': summary.test_id,
            'status': summary.status.value,
            'start_date': summary.start_date.isoformat(),
            'end_date': summary.end_date.isoformat() if summary.end_date else None,
            'total_requests': summary.total_requests,
            'version_stats': summary.version_stats,
            'statistical_significance': summary.statistical_significance,
            'recommendations': summary.recommendations,
            'winner': summary.winner
        }
    
    def benchmark_models(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Run comprehensive model benchmarks."""
        if not self.benchmark:
            raise MLServiceError("Benchmark tool not available")
        
        # Benchmark both models
        results = {}
        
        if self.threat_detector:
            threat_results = self.benchmark.benchmark_model(
                model=self.threat_detector,
                model_name="threat_detection",
                config=config
            )
            results['threat_detection'] = threat_results
        
        if self.vulnerability_assessor:
            vuln_results = self.benchmark.benchmark_model(
                model=self.vulnerability_assessor,
                model_name="vulnerability_assessment",
                config=config
            )
            results['vulnerability_assessment'] = vuln_results
        
        return results
    
    def get_model_metrics(self) -> Dict[str, Any]:
        """Get comprehensive model performance metrics."""
        metrics = {}
        
        if self.health_monitor:
            # Get health metrics for both models
            threat_health = self.health_monitor.check_model_health('threat_detection')
            vuln_health = self.health_monitor.check_model_health('vulnerability_assessment')
            
            metrics['model_health'] = {
                'threat_detection': {
                    'status': threat_health.status.value,
                    'accuracy': threat_health.accuracy,
                    'latency_ms': threat_health.avg_latency_ms,
                    'error_rate': threat_health.error_rate,
                    'drift_score': threat_health.drift_score
                },
                'vulnerability_assessment': {
                    'status': vuln_health.status.value,
                    'accuracy': vuln_health.accuracy,
                    'latency_ms': vuln_health.avg_latency_ms,
                    'error_rate': vuln_health.error_rate,
                    'drift_score': vuln_health.drift_score
                }
            }
        
        # Add service metrics
        metrics['service'] = self.metrics.copy()
        
        return metrics
    
    def shutdown(self) -> bool:
        """Gracefully shutdown the ML service."""
        try:
            logger.info("Shutting down ML service...")
            
            # Stop streaming
            self.stop_streaming()
            
            # Stop monitoring
            if self.health_monitor:
                self.health_monitor.stop_monitoring()
            
            if self.auto_retrainer:
                self.auto_retrainer.stop_scheduler()
            
            # Shutdown executor
            self.executor.shutdown(wait=True)
            
            # Update status
            with self.service_lock:
                self.status = ServiceStatus.STOPPED
            
            logger.info("ML service shutdown completed")
            return True
            
        except Exception as e:
            logger.error(f"Error during shutdown: {str(e)}")
            return False

# Global service instance
_ml_service: Optional[MLService] = None

def get_ml_service() -> MLService:
    """Get global ML service instance."""
    global _ml_service
    if _ml_service is None:
        _ml_service = MLService()
    return _ml_service

# Convenience functions for common operations
async def predict_threat(data: Dict[str, Any], user_id: Optional[str] = None, 
                        ab_test_id: Optional[str] = None) -> PredictionResponse:
    """Convenience function for threat detection."""
    service = get_ml_service()
    request = PredictionRequest(
        request_id=f"threat_{int(datetime.now().timestamp())}",
        model_type="threat_detection",
        data=data,
        user_id=user_id,
        ab_test_id=ab_test_id
    )
    return await service.predict(request)

async def predict_vulnerability(data: Dict[str, Any], user_id: Optional[str] = None,
                               ab_test_id: Optional[str] = None) -> PredictionResponse:
    """Convenience function for vulnerability assessment."""
    service = get_ml_service()
    request = PredictionRequest(
        request_id=f"vuln_{int(datetime.now().timestamp())}",
        model_type="vulnerability_assessment",
        data=data,
        user_id=user_id,
        ab_test_id=ab_test_id
    )
    return await service.predict(request)

def get_service_health() -> ServiceHealth:
    """Get current service health status."""
    service = get_ml_service()
    return service.get_health()

def initialize_ml_service() -> bool:
    """Initialize the ML service with all components."""
    service = get_ml_service()
    return service.initialize()