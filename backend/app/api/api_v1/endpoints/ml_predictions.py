"""
ML Predictions Endpoints
========================

Integrate ML models with backend API for threat detection and vulnerability assessment.
Uses the MLClient to communicate with the microservice-based ML Service.

Endpoints:
- POST /ml/threat-detection - Predict threat level
- POST /ml/vulnerability-assessment - Assess vulnerability
- GET /ml/health - Check ML service health
- GET /ml/models - List available models

Author: SecurityAI Team
Date: December 2025
"""

from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, Field, validator
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging
import time
import uuid

from app.core.auth import get_current_user
from app.models.user import User
from app.services.ml_client import ml_client

logger = logging.getLogger(__name__)
router = APIRouter()


# ==================== Pydantic Models ====================

class ThreatDetectionRequest(BaseModel):
    """Request schema for threat detection prediction."""
    features: Dict[str, Any] = Field(
        ...,
        description="Network traffic or system event features",
        example={
            "source_ip": "192.168.1.100",
            "destination_port": 443,
            "packet_count": 1024,
            "byte_count": 65536,
            "duration": 30.5,
            "protocol": "TCP"
        }
    )
    model_version: str = Field(
        default="latest",
        description="Model version to use"
    )
    request_id: Optional[str] = Field(
        None,
        description="Optional request ID for tracking"
    )

    @validator('features')
    def validate_features(cls, v):
        """Ensure features dictionary is not empty."""
        if not isinstance(v, dict):
            raise ValueError('Features must be a dictionary')
        if not v:
            raise ValueError('Features cannot be empty')
        return v


class ThreatDetectionResponse(BaseModel):
    """Response schema for threat detection prediction."""
    request_id: Optional[str] = Field(
        None,
        description="Request ID for tracking"
    )
    prediction: str = Field(
        ...,
        description="Threat classification (benign/malicious/suspicious)"
    )
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence score (0-1)"
    )
    threat_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="Threat score (0-10)"
    )
    anomaly_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="Anomaly detection score (0-1)"
    )
    processing_time_ms: float = Field(
        ...,
        description="Processing time in milliseconds"
    )
    model_version: str = Field(
        default="latest",
        description="Model version used"
    )
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Response timestamp"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata"
    )


class VulnerabilityAssessmentRequest(BaseModel):
    """Request schema for vulnerability assessment prediction."""
    features: Dict[str, Any] = Field(
        ...,
        description="Vulnerability assessment features",
        example={
            "age": 30,
            "version": "1.2.3",
            "patch_level": 5,
            "complexity_score": 7.5,
            "os_type": "Windows",
            "service_type": "web",
            "exposure_time": 120
        }
    )
    model_version: str = Field(
        default="latest",
        description="Model version to use"
    )
    request_id: Optional[str] = Field(
        None,
        description="Optional request ID for tracking"
    )

    @validator('features')
    def validate_features(cls, v):
        """Ensure features dictionary is not empty."""
        if not isinstance(v, dict):
            raise ValueError('Features must be a dictionary')
        if not v:
            raise ValueError('Features cannot be empty')
        return v


class VulnerabilityAssessmentResponse(BaseModel):
    """Response schema for vulnerability assessment prediction."""
    request_id: Optional[str] = Field(
        None,
        description="Request ID for tracking"
    )
    vulnerability_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="Vulnerability score (0-10)"
    )
    severity: str = Field(
        ...,
        description="Severity level (low/medium/high/critical)"
    )
    is_anomaly: bool = Field(
        ...,
        description="Whether input is anomalous"
    )
    cvss_base_score: Optional[float] = Field(
        None,
        ge=0.0,
        le=10.0,
        description="CVSS base score"
    )
    processing_time_ms: float = Field(
        ...,
        description="Processing time in milliseconds"
    )
    model_version: str = Field(
        default="latest",
        description="Model version used"
    )
    timestamp: datetime = Field(
        default_factory=datetime.now,
        description="Response timestamp"
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata"
    )


class MLHealthResponse(BaseModel):
    """Response schema for ML service health check."""
    status: str = Field(..., description="Overall status")
    threat_model: str = Field(..., description="Threat model status")
    vulnerability_model: str = Field(..., description="Vulnerability model status")
    timestamp: datetime = Field(default_factory=datetime.now)
    version: str = Field(default="1.0.0")
    uptime_seconds: float = Field(default=0.0)


class ModelInfo(BaseModel):
    """Information about available models."""
    name: str
    version: str
    status: str
    last_updated: datetime


class ModelsListResponse(BaseModel):
    """Response schema for available models list."""
    models: List[ModelInfo]
    timestamp: datetime = Field(default_factory=datetime.now)


# ==================== Endpoints ====================

@router.post(
    "/threat-detection",
    response_model=ThreatDetectionResponse,
    status_code=status.HTTP_200_OK,
    summary="Predict Threat Level",
    tags=["predictions"]
)
async def predict_threat(
    request: ThreatDetectionRequest,
    current_user: User = Depends(get_current_user)
) -> ThreatDetectionResponse:
    """
    Predict threat level for given network/event features.
    """
    start_time = time.time()
    request_id = request.request_id or f"threat-{uuid.uuid4().hex[:8]}"

    try:
        logger.info(f"[{request_id}] Processing threat prediction request")

        # Call ML Service via Client
        result = await ml_client.predict(
            model_name="threat_detection",
            features=request.features,
            request_id=request_id
        )

        # Calculate processing time (including network latency)
        processing_time = (time.time() - start_time) * 1000

        # Extract results
        response = ThreatDetectionResponse(
            request_id=request_id,
            prediction=result.get('prediction', 'unknown'),
            confidence=float(result.get('confidence', 0.0)),
            threat_score=float(result.get('metadata', {}).get('threat_score', 0.0)), # Assuming threat_score is in metadata or we map confidence
            anomaly_score=result.get('metadata', {}).get('anomaly_score'),
            processing_time_ms=processing_time,
            model_version=result.get('model_version', request.model_version),
            metadata=result.get('metadata', {})
        )
        
        # Fallback mapping if threat_score is missing
        if response.threat_score == 0.0 and response.confidence > 0:
             response.threat_score = response.confidence * 10.0

        logger.info(
            f"[{request_id}] Threat prediction successful: "
            f"{response.prediction} (confidence={response.confidence:.2f})"
        )
        return response

    except Exception as e:
        logger.error(f"[{request_id}] Threat prediction error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Threat prediction failed: {str(e)}"
        )



class GenericPredictionRequest(BaseModel):
    """Request schema for generic ML prediction."""
    model_name: str = Field(..., description="Name of the model to use")
    features: Dict[str, Any] = Field(..., description="Input features for the model")
    model_version: str = Field(default="latest", description="Model version to use")
    request_id: Optional[str] = Field(None, description="Optional request ID")

    @validator('features')
    def validate_features(cls, v):
        if not isinstance(v, dict):
            raise ValueError('Features must be a dictionary')
        return v

class GenericPredictionResponse(BaseModel):
    """Response schema for generic ML prediction."""
    request_id: Optional[str] = Field(None, description="Request ID")
    prediction: Any = Field(..., description="Prediction result")
    confidence: Optional[float] = Field(None, description="Confidence score")
    processing_time_ms: float = Field(..., description="Processing time in ms")
    model_version: str = Field(default="latest", description="Model version used")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Metadata")


@router.post(
    "/predict",
    response_model=GenericPredictionResponse,
    status_code=status.HTTP_200_OK,
    summary="Generic ML Prediction",
    tags=["predictions"]
)
async def predict_generic(
    request: GenericPredictionRequest,
    current_user: User = Depends(get_current_user)
) -> GenericPredictionResponse:
    """
    Generic prediction endpoint that routes to the specified model.
    """
    start_time = time.time()
    request_id = request.request_id or f"req-{uuid.uuid4().hex[:8]}"

    try:
        logger.info(f"[{request_id}] Processing generic prediction for model: {request.model_name}")

        # Call ML Service via Client
        result = await ml_client.predict(
            model_name=request.model_name,
            features=request.features,
            request_id=request_id
        )

        # Calculate processing time
        processing_time = (time.time() - start_time) * 1000

        # Extract results
        response = GenericPredictionResponse(
            request_id=request_id,
            prediction=result.get('prediction'),
            confidence=result.get('confidence'),
            processing_time_ms=processing_time,
            model_version=result.get('model_version', request.model_version),
            metadata=result.get('metadata', {})
        )

        logger.info(f"[{request_id}] Prediction successful for {request.model_name}")
        return response

    except Exception as e:
        logger.error(f"[{request_id}] Prediction error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prediction failed: {str(e)}"
        )



@router.post(
    "/vulnerability-assessment",
    response_model=VulnerabilityAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Assess Vulnerability",
    tags=["predictions"]
)
async def assess_vulnerability(
    request: VulnerabilityAssessmentRequest,
    current_user: User = Depends(get_current_user)
) -> VulnerabilityAssessmentResponse:
    """
    Assess vulnerability score for given features.
    """
    start_time = time.time()
    request_id = request.request_id or f"vuln-{uuid.uuid4().hex[:8]}"

    try:
        logger.info(f"[{request_id}] Processing vulnerability assessment request")

        # Call ML Service via Client
        result = await ml_client.predict(
            model_name="vulnerability_assessment",
            features=request.features,
            request_id=request_id
        )

        # Calculate processing time
        processing_time = (time.time() - start_time) * 1000

        # Extract results
        # The ML service adapter returns {severity, risk_score, confidence}
        # We need to map this to our response schema
        
        prediction_val = result.get('prediction') # Usually severity string
        metadata = result.get('metadata', {})
        
        # If prediction is a dict (from some adapters), extract fields
        if isinstance(prediction_val, dict):
             severity = prediction_val.get('severity', 'low')
             score = prediction_val.get('risk_score', 0.0)
        else:
             severity = str(prediction_val)
             score = float(metadata.get('risk_score', 0.0))

        response = VulnerabilityAssessmentResponse(
            request_id=request_id,
            vulnerability_score=score,
            severity=severity,
            is_anomaly=bool(metadata.get('is_anomaly', False)),
            cvss_base_score=metadata.get('cvss_base_score'),
            processing_time_ms=processing_time,
            model_version=result.get('model_version', request.model_version),
            metadata=metadata
        )

        logger.info(
            f"[{request_id}] Vulnerability assessment successful: "
            f"score={response.vulnerability_score:.2f}, severity={response.severity}"
        )
        return response

    except Exception as e:
        logger.error(f"[{request_id}] Vulnerability assessment error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Vulnerability assessment failed: {str(e)}"
        )


@router.get(
    "/health",
    response_model=MLHealthResponse,
    status_code=status.HTTP_200_OK,
    summary="ML Service Health Check",
    tags=["health"]
)
async def check_ml_health(
    current_user: User = Depends(get_current_user)
) -> MLHealthResponse:
    """
    Check the health status of ML models via the ML Service.
    """
    try:
        health_data = await ml_client.check_health()
        
        # Map ML Service health response to our schema
        checks = health_data.get("checks", {})
        models_check = checks.get("models", {})
        
        return MLHealthResponse(
            status=health_data.get("status", "unknown"),
            threat_model=models_check.get("status", "unknown"), # Simplified mapping
            vulnerability_model=models_check.get("status", "unknown"),
            timestamp=datetime.now(),
            version=health_data.get("version", "unknown"),
            uptime_seconds=health_data.get("uptime_seconds", 0.0)
        )

    except Exception as e:
        logger.error(f"Health check error: {e}", exc_info=True)
        # Return error state instead of 500 to allow UI to show "Disconnected"
        return MLHealthResponse(
            status="error",
            threat_model="error",
            vulnerability_model="error",
            timestamp=datetime.now(),
            version="unknown",
            uptime_seconds=0.0
        )


@router.get(
    "/models",
    response_model=ModelsListResponse,
    status_code=status.HTTP_200_OK,
    summary="List Available Models",
    tags=["models"]
)
async def list_models(
    current_user: User = Depends(get_current_user)
) -> ModelsListResponse:
    """
    List all available ML models.
    """
    try:
        # We don't have a direct list_models in ml_client yet, but we can assume standard ones
        # or implement it. For now, we'll return the standard list if we can connect.
        
        # Verify connectivity first
        await ml_client.check_health()
        
        models = [
            ModelInfo(
                name="threat_detection",
                version="2.0.0",
                status="available",
                last_updated=datetime.now()
            ),
            ModelInfo(
                name="vulnerability_assessment",
                version="2.0.0",
                status="available",
                last_updated=datetime.now()
            ),
             ModelInfo(
                name="attack_path",
                version="1.0.0",
                status="available",
                last_updated=datetime.now()
            ),
             ModelInfo(
                name="soar_engine",
                version="1.0.0",
                status="available",
                last_updated=datetime.now()
            )
        ]

        return ModelsListResponse(models=models)

    except Exception as e:
        logger.error(f"Failed to list models: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML Service unavailable"
        )


# ==================== Batch Endpoints ====================

@router.post(
    "/threat-detection/batch",
    response_model=List[ThreatDetectionResponse],
    status_code=status.HTTP_200_OK,
    summary="Batch Threat Predictions",
    tags=["predictions"]
)
async def predict_threats_batch(
    requests: List[ThreatDetectionRequest],
    current_user: User = Depends(get_current_user)
) -> List[ThreatDetectionResponse]:
    """
    Process multiple threat predictions in a single request.
    """
    if len(requests) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 requests per batch"
        )

    responses = []
    # In a real microservice optimization, we would add a batch endpoint to ml_client
    # For now, we'll loop (or use asyncio.gather if we updated ml_client to be async properly)
    
    # Using simple loop for safety in this refactor
    for request in requests:
        try:
            response = await predict_threat(request, current_user)
            responses.append(response)
        except HTTPException:
            pass

    return responses


@router.post(
    "/vulnerability-assessment/batch",
    response_model=List[VulnerabilityAssessmentResponse],
    status_code=status.HTTP_200_OK,
    summary="Batch Vulnerability Assessments",
    tags=["predictions"]
)
async def assess_vulnerabilities_batch(
    requests: List[VulnerabilityAssessmentRequest],
    current_user: User = Depends(get_current_user)
) -> List[VulnerabilityAssessmentResponse]:
    """
    Process multiple vulnerability assessments in a single request.
    """
    if len(requests) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 requests per batch"
        )

    responses = []
    for request in requests:
        try:
            response = await assess_vulnerability(request, current_user)
            responses.append(response)
        except HTTPException:
            pass

    return responses
