"""
ML Predictions Endpoints
========================

Integrate ML models with backend API for threat detection and vulnerability assessment.

Endpoints:
- POST /ml/threat-detection - Predict threat level
- POST /ml/vulnerability-assessment - Assess vulnerability
- GET /ml/health - Check ML service health
- GET /ml/models - List available models

Author: SecurityAI Team
Date: November 2025
"""

from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, Field, validator
from typing import Dict, Any, Optional, List
from datetime import datetime
import logging
import time
import sys
import os

# Add ml module to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../../../ml'))

from app.core.auth import get_current_user
from app.models.user import User

# Import ML models with error handling
_threat_model = None
_vuln_model = None
_import_error = None

try:
    from ml.app.models.threat_detection import ThreatDetectionModel
    from ml.app.models.vulnerability_assessment import VulnerabilityAssessmentModel
    _threat_model_class = ThreatDetectionModel
    _vuln_model_class = VulnerabilityAssessmentModel
except ImportError as e:
    _import_error = f"Failed to import ML models: {str(e)}"
    logging.error(_import_error)

logger = logging.getLogger(__name__)
router = APIRouter()


# ==================== Model Initialization ====================

def get_threat_model():
    """Get or initialize threat detection model."""
    global _threat_model
    if _threat_model is None:
        if _import_error:
            raise RuntimeError(f"ML models not available: {_import_error}")
        try:
            _threat_model = _threat_model_class()
            logger.info("Threat detection model initialized")
        except Exception as e:
            logger.error(f"Failed to initialize threat model: {e}")
            raise
    return _threat_model


def get_vuln_model():
    """Get or initialize vulnerability assessment model."""
    global _vuln_model
    if _vuln_model is None:
        if _import_error:
            raise RuntimeError(f"ML models not available: {_import_error}")
        try:
            _vuln_model = _vuln_model_class()
            logger.info("Vulnerability assessment model initialized")
        except Exception as e:
            logger.error(f"Failed to initialize vulnerability model: {e}")
            raise
    return _vuln_model


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

    class Config:
        schema_extra = {
            "example": {
                "request_id": "req-123",
                "prediction": "malicious",
                "confidence": 0.92,
                "threat_score": 8.5,
                "anomaly_score": 0.87,
                "processing_time_ms": 45.3,
                "model_version": "latest",
                "timestamp": "2025-11-14T10:30:00Z",
                "metadata": {"ensemble_vote": 3, "model_agreement": 100}
            }
        }


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

    class Config:
        schema_extra = {
            "example": {
                "request_id": "req-456",
                "vulnerability_score": 7.8,
                "severity": "high",
                "is_anomaly": False,
                "cvss_base_score": 7.8,
                "processing_time_ms": 52.1,
                "model_version": "latest",
                "timestamp": "2025-11-14T10:30:00Z",
                "metadata": {"ensemble_vote": 3, "model_agreement": 100}
            }
        }


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

    **Request Body:**
    - `features`: Dictionary of network/event features
    - `model_version`: Version of model to use (default: latest)
    - `request_id`: Optional request ID for tracking

    **Response:**
    - `prediction`: Threat classification (benign/malicious/suspicious)
    - `confidence`: Confidence score (0-1)
    - `threat_score`: Threat score (0-10)
    - `anomaly_score`: Anomaly detection score
    - `processing_time_ms`: Time taken for prediction

    **Errors:**
    - 400: Invalid features
    - 401: Unauthorized
    - 500: Model prediction failed
    """
    start_time = time.time()
    request_id = request.request_id or f"threat-{int(start_time*1000)}"

    try:
        logger.info(f"[{request_id}] Processing threat prediction request")

        # Validate features
        if not request.features:
            raise ValueError("Features cannot be empty")

        # Get model
        model = get_threat_model()

        # Make prediction
        logger.debug(f"[{request_id}] Calling threat detection model")
        result = model.predict(request.features)

        # Calculate processing time
        processing_time = (time.time() - start_time) * 1000

        # Extract results
        response = ThreatDetectionResponse(
            request_id=request_id,
            prediction=result.get('prediction', 'unknown'),
            confidence=float(result.get('confidence', 0.0)),
            threat_score=float(result.get('threat_score', 0.0)),
            anomaly_score=result.get('anomaly_score'),
            processing_time_ms=processing_time,
            model_version=request.model_version,
            metadata=result.get('metadata', {})
        )

        logger.info(
            f"[{request_id}] Threat prediction successful: "
            f"{response.prediction} (confidence={response.confidence:.2f})"
        )
        return response

    except ValueError as e:
        logger.warning(f"[{request_id}] Validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid request: {str(e)}"
        )
    except RuntimeError as e:
        logger.error(f"[{request_id}] Model not available: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML service not available"
        )
    except Exception as e:
        logger.error(f"[{request_id}] Threat prediction error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Threat prediction failed"
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

    **Request Body:**
    - `features`: Dictionary of vulnerability features
    - `model_version`: Version of model to use (default: latest)
    - `request_id`: Optional request ID for tracking

    **Response:**
    - `vulnerability_score`: Score (0-10)
    - `severity`: Severity level (low/medium/high/critical)
    - `is_anomaly`: Whether input is anomalous
    - `cvss_base_score`: CVSS base score
    - `processing_time_ms`: Time taken for assessment

    **Errors:**
    - 400: Invalid features
    - 401: Unauthorized
    - 500: Assessment failed
    """
    start_time = time.time()
    request_id = request.request_id or f"vuln-{int(start_time*1000)}"

    try:
        logger.info(f"[{request_id}] Processing vulnerability assessment request")

        # Validate features
        if not request.features:
            raise ValueError("Features cannot be empty")

        # Get model
        model = get_vuln_model()

        # Make prediction
        logger.debug(f"[{request_id}] Calling vulnerability assessment model")
        result = model.predict(request.features)

        # Calculate processing time
        processing_time = (time.time() - start_time) * 1000

        # Extract results
        response = VulnerabilityAssessmentResponse(
            request_id=request_id,
            vulnerability_score=float(result.get('vulnerability_score', 0.0)),
            severity=result.get('severity', 'low'),
            is_anomaly=bool(result.get('is_anomaly', False)),
            cvss_base_score=result.get('cvss_base_score'),
            processing_time_ms=processing_time,
            model_version=request.model_version,
            metadata=result.get('metadata', {})
        )

        logger.info(
            f"[{request_id}] Vulnerability assessment successful: "
            f"score={response.vulnerability_score:.2f}, severity={response.severity}"
        )
        return response

    except ValueError as e:
        logger.warning(f"[{request_id}] Validation error: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid request: {str(e)}"
        )
    except RuntimeError as e:
        logger.error(f"[{request_id}] Model not available: {e}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="ML service not available"
        )
    except Exception as e:
        logger.error(f"[{request_id}] Vulnerability assessment error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Vulnerability assessment failed"
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
    Check the health status of ML models.

    **Response:**
    - `status`: Overall ML service status
    - `threat_model`: Threat detection model status
    - `vulnerability_model`: Vulnerability assessment model status
    - `timestamp`: Health check timestamp
    - `version`: ML service version

    **Returns:**
    - 200: Both models healthy
    - 503: One or more models unavailable
    """
    try:
        # Check threat model
        try:
            get_threat_model()
            threat_status = "ready"
        except Exception as e:
            logger.warning(f"Threat model health check failed: {e}")
            threat_status = "error"

        # Check vulnerability model
        try:
            get_vuln_model()
            vuln_status = "ready"
        except Exception as e:
            logger.warning(f"Vulnerability model health check failed: {e}")
            vuln_status = "error"

        # Determine overall status
        overall_status = "healthy" if (threat_status == "ready" and vuln_status == "ready") else "degraded"

        response = MLHealthResponse(
            status=overall_status,
            threat_model=threat_status,
            vulnerability_model=vuln_status
        )

        logger.info(f"ML health check: {overall_status}")
        return response

    except Exception as e:
        logger.error(f"Health check error: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Health check failed"
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

    **Response:**
    - `models`: List of available models with metadata
    - `timestamp`: Response timestamp

    **Returns:**
    - 200: List of models
    """
    try:
        models = [
            ModelInfo(
                name="threat_detection",
                version="1.0.0",
                status="ready",
                last_updated=datetime.now()
            ),
            ModelInfo(
                name="vulnerability_assessment",
                version="1.0.0",
                status="ready",
                last_updated=datetime.now()
            )
        ]

        return ModelsListResponse(models=models)

    except Exception as e:
        logger.error(f"Failed to list models: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list models"
        )


# ==================== Batch Endpoints (Optional) ====================

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

    **Request Body:**
    - `requests`: List of threat detection requests

    **Response:**
    - List of threat detection responses in same order

    **Limits:**
    - Maximum 100 requests per batch
    """
    if len(requests) > 100:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum 100 requests per batch"
        )

    responses = []
    for request in requests:
        try:
            response = await predict_threat(request, current_user)
            responses.append(response)
        except HTTPException:
            # Continue processing other requests
            pass

    logger.info(f"Batch threat prediction: processed {len(responses)}/{len(requests)} requests")
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

    **Request Body:**
    - `requests`: List of vulnerability assessment requests

    **Response:**
    - List of vulnerability assessment responses in same order

    **Limits:**
    - Maximum 100 requests per batch
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
            # Continue processing other requests
            pass

    logger.info(f"Batch vulnerability assessment: processed {len(responses)}/{len(requests)} requests")
    return responses
