#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Enhanced FastAPI application for the SecurityAI ML Service.

This service provides machine learning capabilities for:
- Threat detection and classification
- Vulnerability assessment
- Security analytics

Enhanced with:
- Advanced error handling and circuit breakers
- Comprehensive monitoring and alerting
- Performance optimization and caching
- Structured logging and audit trails
- Real-time health checks
- Resource management
"""

import os
import asyncio
import time
import uuid
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field, ValidationError
import uvicorn
import mlflow
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

from core.config import settings, ModelType
from core.exceptions import (
    SecurityAIException, ModelError, PredictionError, ResourceExhaustionError,
    error_handler, CircuitBreakerError
)
from core.monitoring import metrics_collector, health_checker
from core.model_manager import model_manager, PredictionRequest, PredictionResult
from core.logging_system import (
    app_logger, alert_manager, performance_tracker, log_context,
    track_performance, log_security_event, create_alert, AlertSeverity
)
from models.threat_detection import ThreatDetectionModel
from models.vulnerability_assessment import VulnerabilityAssessmentModel
from streaming.real_time_detector import (
    real_time_detector, StreamEvent, StreamEventType, ThreatDetectionResult,
    start_real_time_detection, stop_real_time_detection, submit_event,
    add_threat_callback, get_stream_statistics
)


# Pydantic Models
class PredictionInput(BaseModel):
    """Input model for predictions."""
    features: Dict[str, Any] = Field(..., description="Feature data for prediction")
    model_name: str = Field(default="threat_detection", description="Name of the model to use")
    model_version: str = Field(default="latest", description="Version of the model")
    request_id: Optional[str] = Field(default=None, description="Optional request ID for tracking")
    timeout: Optional[float] = Field(default=30.0, ge=1.0, le=300.0, description="Request timeout in seconds")

    class Config:
        schema_extra = {
            "example": {
                "features": {
                    "source_ip": "192.168.1.100",
                    "destination_port": 80,
                    "packet_size": 1024,
                    "protocol": "TCP"
                },
                "model_name": "threat_detection",
                "model_version": "latest",
                "timeout": 30.0
            }
        }


class PredictionOutput(BaseModel):
    """Output model for predictions."""
    request_id: str = Field(..., description="Request ID for tracking")
    prediction: Any = Field(..., description="Model prediction result")
    confidence: Optional[float] = Field(None, ge=0.0, le=1.0, description="Prediction confidence score")
    processing_time_ms: float = Field(..., ge=0.0, description="Processing time in milliseconds")
    model_info: Dict[str, Any] = Field(..., description="Model metadata")
    timestamp: datetime = Field(default_factory=datetime.now, description="Response timestamp")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class BatchPredictionInput(BaseModel):
    """Input model for batch predictions."""
    requests: List[PredictionInput] = Field(..., max_items=100, description="List of prediction requests")
    parallel: bool = Field(default=True, description="Process requests in parallel")


class BatchPredictionOutput(BaseModel):
    """Output model for batch predictions."""
    results: List[PredictionOutput] = Field(..., description="Prediction results")
    total_requests: int = Field(..., description="Total number of requests")
    successful_requests: int = Field(..., description="Number of successful requests")
    failed_requests: int = Field(..., description="Number of failed requests")
    total_processing_time_ms: float = Field(..., description="Total processing time")
    errors: List[Dict[str, Any]] = Field(default_factory=list, description="Error details")


class ModelInfo(BaseModel):
    """Model information."""
    name: str
    type: str
    version: str
    status: str
    description: Optional[str] = None
    metrics: Dict[str, Any] = Field(default_factory=dict)
    last_updated: datetime


class HealthStatus(BaseModel):
    """Health check status."""
    status: str = Field(..., description="Overall health status")
    timestamp: datetime = Field(default_factory=datetime.now)
    version: str = Field(default="1.0.0")
    uptime_seconds: float
    checks: Dict[str, Any] = Field(default_factory=dict)
    metrics: Dict[str, Any] = Field(default_factory=dict)


class AlertResponse(BaseModel):
    """Alert information."""
    id: str
    title: str
    description: str
    severity: str
    timestamp: datetime
    resolved: bool
    source: str


class StreamEventInput(BaseModel):
    """Input model for streaming events."""
    event_type: str = Field(..., description="Type of event (network_traffic, system_log, etc.)")
    source: str = Field(..., description="Source of the event")
    data: Dict[str, Any] = Field(..., description="Event data")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class StreamEventResponse(BaseModel):
    """Response for submitted streaming events."""
    event_id: str
    status: str
    message: str
    timestamp: datetime = Field(default_factory=datetime.now)


class ThreatDetectionResponse(BaseModel):
    """Response model for threat detection results."""
    event_id: str
    threat_level: str
    confidence: float
    threat_type: str
    description: str
    indicators: List[str]
    recommended_actions: List[str]
    processing_time_ms: float
    model_version: str
    metadata: Dict[str, Any]


class StreamStatsResponse(BaseModel):
    """Response model for streaming statistics."""
    processing: Dict[str, Any]
    analytics: Dict[str, Any]
    queue_size: int
    is_running: bool
    callbacks_registered: int


# Application lifespan management
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    # Startup
    app_logger.info("Starting SecurityAI ML Service")
    
    try:
        # Initialize MLflow
        mlflow.set_tracking_uri(settings.mlflow_tracking_uri)
        app_logger.info(f"MLflow tracking URI: {settings.mlflow_tracking_uri}")
        
        # Start model manager batch processor
        await model_manager.start_batch_processor()
        
        # Pre-load models if configured
        if settings.preload_models:
            for model_type in ModelType:
                try:
                    await model_manager.load_model(model_type.value)
                    app_logger.info(f"Pre-loaded model: {model_type.value}")
                except Exception as e:
                    app_logger.warning(f"Failed to pre-load model {model_type.value}: {e}")
        
        # Start real-time threat detection if enabled
        if settings.enable_real_time_detection:
            try:
                # Start real-time detector in background
                asyncio.create_task(start_real_time_detection())
                app_logger.info("Real-time threat detection started")
            except Exception as e:
                app_logger.error(f"Failed to start real-time detection: {e}")
        
        app_logger.success("SecurityAI ML Service started successfully")
        
        yield
        
    finally:
        # Shutdown
        app_logger.info("Shutting down SecurityAI ML Service")
        
        try:
            await model_manager.stop_batch_processor()
            app_logger.info("Model manager stopped")
        except Exception as e:
            app_logger.error(f"Error stopping model manager: {e}")
        
        # Stop real-time detection
        try:
            await stop_real_time_detection()
            app_logger.info("Real-time detection stopped")
        except Exception as e:
            app_logger.error(f"Error stopping real-time detection: {e}")
        
        app_logger.info("SecurityAI ML Service shutdown complete")


# Initialize FastAPI app
app = FastAPI(
    title="SecurityAI ML Service",
    description="Enhanced ML service for cybersecurity threat detection and vulnerability assessment",
    version="2.0.0",
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url="/redoc" if settings.enable_docs else None,
    lifespan=lifespan
)

# Store startup time for uptime calculation
app.state.startup_time = time.time()

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

if settings.trusted_hosts:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=settings.trusted_hosts
    )


# Request/Response middleware for logging and monitoring
@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Log requests and responses with performance tracking."""
    start_time = time.time()
    request_id = str(uuid.uuid4())
    
    # Extract client info
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "unknown")
    
    with log_context(
        request_id=request_id,
        endpoint=str(request.url.path),
        method=request.method,
        ip_address=client_ip,
        user_agent=user_agent
    ):
        app_logger.info(f"Request started: {request.method} {request.url.path}")
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate processing time
            processing_time = time.time() - start_time
            
            # Update metrics
            metrics_collector.request_counter.labels(
                method=request.method,
                endpoint=request.url.path,
                status_code=response.status_code
            ).inc()
            
            metrics_collector.request_duration.labels(
                method=request.method,
                endpoint=request.url.path
            ).observe(processing_time)
            
            # Log response
            app_logger.info(
                f"Request completed: {response.status_code} in {processing_time*1000:.1f}ms",
                status_code=response.status_code,
                processing_time_ms=processing_time * 1000
            )
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except Exception as e:
            processing_time = time.time() - start_time
            
            # Update error metrics
            metrics_collector.error_counter.labels(
                endpoint=request.url.path,
                error_type=type(e).__name__
            ).inc()
            
            # Log error
            app_logger.error(
                f"Request failed: {type(e).__name__} in {processing_time*1000:.1f}ms",
                error=e,
                processing_time_ms=processing_time * 1000
            )
            
            raise


# Exception handlers
@app.exception_handler(SecurityAIException)
async def security_ai_exception_handler(request: Request, exc: SecurityAIException):
    """Handle SecurityAI custom exceptions."""
    app_logger.error(f"SecurityAI exception: {exc.message}", error=exc)
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.error_code,
            "message": exc.message,
            "details": exc.details,
            "timestamp": datetime.now().isoformat(),
            "request_id": getattr(request.state, 'request_id', None)
        }
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Handle request validation errors."""
    app_logger.warning(f"Validation error: {exc.errors()}")
    
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": "validation_error",
            "message": "Request validation failed",
            "details": exc.errors(),
            "timestamp": datetime.now().isoformat()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions."""
    app_logger.critical(f"Unexpected error: {str(exc)}", error=exc)
    
    # Create alert for unexpected errors
    create_alert(
        title="Unexpected Application Error",
        description=f"Unhandled exception in {request.url.path}: {str(exc)}",
        severity=AlertSeverity.HIGH,
        tags={"endpoint": str(request.url.path), "error_type": type(exc).__name__}
    )
    
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "internal_server_error",
            "message": "An unexpected error occurred",
            "timestamp": datetime.now().isoformat(),
            "request_id": getattr(request.state, 'request_id', None)
        }
    )


# Routes
@app.get("/", tags=["General"])
async def root():
    """Root endpoint with service information."""
    return {
        "service": "SecurityAI ML Service",
        "version": "2.0.0",
        "status": "operational",
        "timestamp": datetime.now().isoformat(),
        "documentation": "/docs" if settings.enable_docs else "disabled",
        "health_check": "/health",
        "metrics": "/metrics"
    }


@app.get("/health", response_model=HealthStatus, tags=["Health"])
async def health_check():
    """Comprehensive health check endpoint."""
    uptime = time.time() - app.state.startup_time
    
    # Get health status from model manager
    model_health = await model_manager.health_check()
    
    # Get system health
    system_health = health_checker.check_system_health()
    
    # Determine overall status
    overall_status = "healthy"
    if model_health["status"] == "critical" or system_health["status"] == "critical":
        overall_status = "critical"
    elif model_health["status"] == "warning" or system_health["status"] == "warning":
        overall_status = "warning"
    
    return HealthStatus(
        status=overall_status,
        uptime_seconds=uptime,
        checks={
            "models": model_health,
            "system": system_health,
            "alerts": {
                "active_alerts": len(alert_manager.get_active_alerts()),
                "status": "healthy" if len(alert_manager.get_active_alerts()) == 0 else "warning"
            }
        },
        metrics={
            "cache_stats": model_manager.get_model_stats()["cache"],
            "performance_stats": performance_tracker.get_performance_stats()
        }
    )


@app.get("/metrics", tags=["Monitoring"])
async def get_metrics():
    """Prometheus metrics endpoint."""
    return PlainTextResponse(
        generate_latest(),
        media_type=CONTENT_TYPE_LATEST
    )


@app.get("/models", response_model=List[ModelInfo], tags=["Models"])
async def list_models():
    """List available models and their information."""
    models = []
    
    for model_type in ModelType:
        try:
            # Try to load model to get info
            model = await model_manager.load_model(model_type.value)
            
            models.append(ModelInfo(
                name=model_type.value,
                type=model_type.name,
                version="latest",
                status="available",
                description=f"{model_type.value.replace('_', ' ').title()} model",
                last_updated=datetime.now()
            ))
        except Exception as e:
            models.append(ModelInfo(
                name=model_type.value,
                type=model_type.name,
                version="latest",
                status="error",
                description=f"Error loading model: {str(e)}",
                last_updated=datetime.now()
            ))
    
    return models


@app.post("/predict", response_model=PredictionOutput, tags=["Prediction"])
async def predict(input_data: PredictionInput, request: Request):
    """Make a single prediction with comprehensive error handling."""
    request_id = input_data.request_id or str(uuid.uuid4())
    
    with log_context(
        request_id=request_id,
        model_name=input_data.model_name,
        endpoint="predict"
    ):
        with track_performance("predict", input_data.model_name):
            try:
                # Validate model name
                if input_data.model_name not in [mt.value for mt in ModelType]:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Unknown model: {input_data.model_name}"
                    )
                
                # Make prediction
                result = await model_manager.predict(
                    model_name=input_data.model_name,
                    features=input_data.features,
                    model_version=input_data.model_version,
                    request_id=request_id
                )
                
                app_logger.info(
                    f"Prediction completed successfully",
                    prediction=result.prediction,
                    confidence=result.confidence,
                    processing_time_ms=result.processing_time_ms
                )
                
                return PredictionOutput(
                    request_id=result.request_id,
                    prediction=result.prediction,
                    confidence=result.confidence,
                    processing_time_ms=result.processing_time_ms,
                    model_info={
                        "name": input_data.model_name,
                        "version": result.model_version,
                        "type": input_data.model_name
                    },
                    metadata=result.metadata
                )
                
            except CircuitBreakerError as e:
                app_logger.warning(f"Circuit breaker open for model {input_data.model_name}")
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail=f"Model {input_data.model_name} is temporarily unavailable"
                )
                
            except PredictionError as e:
                app_logger.error(f"Prediction failed: {e.message}", error=e)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Prediction failed: {e.message}"
                )
                
            except Exception as e:
                app_logger.error(f"Unexpected error in prediction: {str(e)}", error=e)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="An unexpected error occurred during prediction"
                )


@app.post("/batch-predict", response_model=BatchPredictionOutput, tags=["Prediction"])
async def batch_predict(input_data: BatchPredictionInput):
    """Process multiple predictions efficiently."""
    start_time = time.time()
    
    with log_context(endpoint="batch_predict"):
        with track_performance("batch_predict"):
            try:
                # Convert to PredictionRequest objects
                requests = [
                    PredictionRequest(
                        request_id=req.request_id or str(uuid.uuid4()),
                        model_name=req.model_name,
                        features=req.features,
                        timeout=req.timeout
                    )
                    for req in input_data.requests
                ]
                
                # Process batch
                results = await model_manager.batch_predict(requests)
                
                # Convert results
                prediction_outputs = []
                errors = []
                successful_count = 0
                
                for i, result in enumerate(results):
                    if result.metadata.get("error"):
                        errors.append({
                            "index": i,
                            "request_id": result.request_id,
                            "error": result.metadata["error"]
                        })
                    else:
                        successful_count += 1
                        
                    prediction_outputs.append(PredictionOutput(
                        request_id=result.request_id,
                        prediction=result.prediction,
                        confidence=result.confidence,
                        processing_time_ms=result.processing_time_ms,
                        model_info={
                            "name": requests[i].model_name,
                            "version": result.model_version,
                            "type": requests[i].model_name
                        },
                        metadata=result.metadata
                    ))
                
                total_time = (time.time() - start_time) * 1000
                
                app_logger.info(
                    f"Batch prediction completed",
                    total_requests=len(requests),
                    successful_requests=successful_count,
                    failed_requests=len(errors),
                    total_processing_time_ms=total_time
                )
                
                return BatchPredictionOutput(
                    results=prediction_outputs,
                    total_requests=len(requests),
                    successful_requests=successful_count,
                    failed_requests=len(errors),
                    total_processing_time_ms=total_time,
                    errors=errors
                )
                
            except ResourceExhaustionError as e:
                app_logger.warning(f"Resource exhaustion in batch prediction: {e.message}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Resource limit exceeded: {e.message}"
                )
                
            except Exception as e:
                app_logger.error(f"Batch prediction failed: {str(e)}", error=e)
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Batch prediction failed"
                )


@app.get("/stats", tags=["Monitoring"])
async def get_stats():
    """Get comprehensive service statistics."""
    return {
        "models": model_manager.get_model_stats(),
        "alerts": alert_manager.get_alert_stats(),
        "performance": performance_tracker.get_performance_stats(),
        "system": health_checker.get_system_metrics(),
        "uptime_seconds": time.time() - app.state.startup_time
    }


@app.get("/alerts", response_model=List[AlertResponse], tags=["Monitoring"])
async def get_alerts(active_only: bool = True):
    """Get current alerts."""
    if active_only:
        alerts = alert_manager.get_active_alerts()
    else:
        alerts = list(alert_manager.alerts.values())
    
    return [
        AlertResponse(
            id=alert.id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity.value,
            timestamp=alert.timestamp,
            resolved=alert.resolved,
            source=alert.source
        )
        for alert in alerts
    ]


@app.post("/alerts/{alert_id}/resolve", tags=["Monitoring"])
async def resolve_alert(alert_id: str):
    """Resolve an active alert."""
    success = alert_manager.resolve_alert(alert_id)
    
    if success:
        app_logger.info(f"Alert {alert_id} resolved")
        return {"message": f"Alert {alert_id} resolved successfully"}
    else:
         raise HTTPException(
             status_code=status.HTTP_404_NOT_FOUND,
             detail=f"Alert {alert_id} not found or already resolved"
         )


# Streaming endpoints
@app.post("/stream/events", response_model=StreamEventResponse, tags=["Streaming"])
async def submit_stream_event(event_input: StreamEventInput):
    """Submit an event for real-time threat detection."""
    try:
        # Validate event type
        try:
            event_type = StreamEventType(event_input.event_type.lower())
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid event type: {event_input.event_type}"
            )
        
        # Create stream event
        event = StreamEvent(
            event_type=event_type,
            source=event_input.source,
            data=event_input.data,
            metadata=event_input.metadata
        )
        
        # Submit to real-time detector
        await real_time_detector.add_event(event)
        
        app_logger.info(
            f"Stream event submitted",
            event_id=event.id,
            event_type=event_type.value,
            source=event_input.source
        )
        
        return StreamEventResponse(
            event_id=event.id,
            status="accepted",
            message="Event submitted for real-time analysis"
        )
        
    except Exception as e:
        app_logger.error(f"Error submitting stream event: {str(e)}", error=e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to submit event: {str(e)}"
        )


@app.post("/stream/events/batch", tags=["Streaming"])
async def submit_batch_stream_events(events: List[StreamEventInput]):
    """Submit multiple events for real-time threat detection."""
    if len(events) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 events per batch"
        )
    
    results = []
    errors = []
    
    for i, event_input in enumerate(events):
        try:
            # Validate event type
            try:
                event_type = StreamEventType(event_input.event_type.lower())
            except ValueError:
                errors.append({
                    "index": i,
                    "error": f"Invalid event type: {event_input.event_type}"
                })
                continue
            
            # Create and submit event
            event = StreamEvent(
                event_type=event_type,
                source=event_input.source,
                data=event_input.data,
                metadata=event_input.metadata
            )
            
            await real_time_detector.add_event(event)
            
            results.append(StreamEventResponse(
                event_id=event.id,
                status="accepted",
                message="Event submitted for real-time analysis"
            ))
            
        except Exception as e:
            errors.append({
                "index": i,
                "error": str(e)
            })
    
    app_logger.info(
        f"Batch stream events submitted",
        total_events=len(events),
        successful=len(results),
        failed=len(errors)
    )
    
    return {
        "results": results,
        "total_events": len(events),
        "successful_events": len(results),
        "failed_events": len(errors),
        "errors": errors
    }


@app.get("/stream/stats", response_model=StreamStatsResponse, tags=["Streaming"])
async def get_stream_stats():
    """Get real-time streaming statistics."""
    try:
        stats = get_stream_statistics()
        return StreamStatsResponse(**stats)
    except Exception as e:
        app_logger.error(f"Error getting stream stats: {str(e)}", error=e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get streaming statistics"
        )


@app.get("/stream/health", tags=["Streaming"])
async def get_stream_health():
    """Get real-time detection service health."""
    stats = get_stream_statistics()
    
    # Determine health status
    health_status = "healthy"
    issues = []
    
    if not stats["is_running"]:
        health_status = "critical"
        issues.append("Real-time detection service is not running")
    
    if stats["queue_size"] > 8000:
        health_status = "warning" if health_status == "healthy" else health_status
        issues.append(f"High queue size: {stats['queue_size']}")
    
    if stats["processing"]["avg_processing_time"] > 1000:
        health_status = "warning" if health_status == "healthy" else health_status
        issues.append(f"Slow processing: {stats['processing']['avg_processing_time']:.1f}ms avg")
    
    return {
        "status": health_status,
        "is_running": stats["is_running"],
        "queue_size": stats["queue_size"],
        "avg_processing_time_ms": stats["processing"]["avg_processing_time"],
        "events_processed": stats["processing"]["events_processed"],
        "threats_detected": stats["processing"]["threats_detected"],
        "issues": issues,
        "timestamp": datetime.now().isoformat()
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
        access_log=True
    )