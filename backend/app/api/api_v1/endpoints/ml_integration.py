"""
Backend ML Integration - Endpoints using Production ML Models
Connects FastAPI backend to real ML models (SOAR, UEBA, EDR, XDR)
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
import logging

from app.core.auth import get_current_user
from app.db.session import get_db
from app.models.user import User

# Import production ML models
try:
    from ml.app.soar.workflow_engine_prod import get_workflow_engine, WorkflowTemplate, WorkflowStep
    from ml.app.soar.workflow_engine_prod import IsolateEndpointAction, BlockIPAction, SendAlertAction, CreateTicketAction
    from ml.app.soar.workflow_engine_prod import ActionType, WorkflowState
    
    from ml.app.ueba.ueba_prod import get_ueba_system, BehaviorEvent, EntityType, BehaviorCategory
    
    from ml.app.edr.edr_prod import get_edr_system, ProcessEvent, FileEvent, NetworkEvent
    
    from ml.app.retraining_pipeline_prod import get_retraining_pipeline
    
    ML_MODELS_AVAILABLE = True
except ImportError as e:
    ML_MODELS_AVAILABLE = False
    print(f"Warning: ML models not available: {e}")

logger = logging.getLogger(__name__)
router = APIRouter()


# ============================================================================
# SOAR Endpoints (Security Orchestration Automation Response)
# ============================================================================

@router.get("/soar/workflows")
async def list_soar_workflows(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """List available SOAR workflows"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    engine = get_workflow_engine()
    workflows = await engine.list_workflows()
    
    return {
        "success": True,
        "data": workflows,
        "total": len(workflows)
    }


@router.post("/soar/workflows/{workflow_id}/execute")
async def execute_soar_workflow(
    workflow_id: str,
    trigger_event: dict,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Execute a SOAR workflow"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    try:
        engine = get_workflow_engine()
        execution_id = await engine.execute_workflow(workflow_id, trigger_event)
        
        return {
            "success": True,
            "data": {
                "execution_id": execution_id,
                "workflow_id": workflow_id,
                "status": "running"
            }
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/soar/executions/{execution_id}")
async def get_soar_execution_status(
    execution_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get SOAR workflow execution status"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    try:
        engine = get_workflow_engine()
        status = await engine.get_execution_status(execution_id)
        
        return {
            "success": True,
            "data": status
        }
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


# ============================================================================
# UEBA Endpoints (User & Entity Behavior Analytics)
# ============================================================================

@router.post("/ueba/process-event")
async def process_ueba_event(
    event_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Process behavior event for UEBA analysis"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    try:
        ueba = get_ueba_system()
        
        # Create behavior event
        event = BehaviorEvent(
            entity_id=event_data.get("entity_id"),
            entity_type=event_data.get("entity_type", "user"),
            event_type=event_data.get("event_type"),
            source_ip=event_data.get("source_ip", ""),
            location=event_data.get("location", ""),
            resource=event_data.get("resource", ""),
            action=event_data.get("action", ""),
            success=event_data.get("success", True),
            context=event_data.get("context", {})
        )
        
        # Process event
        anomaly = await ueba.process_event(event)
        
        return {
            "success": True,
            "data": {
                "event_id": event.event_id,
                "anomaly_detected": anomaly is not None,
                "anomaly": anomaly.__dict__ if anomaly else None
            }
        }
    except Exception as e:
        logger.error(f"Error processing UEBA event: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ueba/entity-risk/{entity_id}")
async def get_entity_risk(
    entity_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get risk assessment for an entity"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    ueba = get_ueba_system()
    risk = await ueba.get_entity_risk(entity_id)
    
    return {
        "success": True,
        "data": risk
    }


@router.get("/ueba/anomalies/{entity_id}")
async def get_entity_anomalies(
    entity_id: str,
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user)
):
    """Get anomalies for an entity"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    ueba = get_ueba_system()
    anomalies = await ueba.get_anomalies(entity_id)
    
    return {
        "success": True,
        "data": anomalies[-limit:],
        "total": len(anomalies)
    }


# ============================================================================
# EDR Endpoints (Endpoint Detection and Response)
# ============================================================================

@router.post("/edr/endpoints/{endpoint_id}/register")
async def register_edr_endpoint(
    endpoint_id: str,
    endpoint_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Register an EDR endpoint"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    try:
        edr = get_edr_system()
        
        endpoint = await edr.register_endpoint(
            endpoint_id=endpoint_id,
            hostname=endpoint_data.get("hostname"),
            ip_address=endpoint_data.get("ip_address")
        )
        
        return {
            "success": True,
            "data": {
                "endpoint_id": endpoint.endpoint_id,
                "hostname": endpoint.hostname,
                "status": endpoint.status.value
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/edr/endpoints/{endpoint_id}/process-event")
async def process_edr_process_event(
    endpoint_id: str,
    event_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Process process event for EDR analysis"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    try:
        edr = get_edr_system()
        
        process = ProcessEvent(
            process_id=event_data.get("process_id"),
            process_name=event_data.get("process_name"),
            process_path=event_data.get("process_path"),
            parent_process_id=event_data.get("parent_process_id", 0),
            user=event_data.get("user"),
            command_line=event_data.get("command_line", "")
        )
        
        threat = await edr.process_process_event(endpoint_id, process)
        
        return {
            "success": True,
            "data": {
                "threat_detected": threat is not None,
                "threat": threat.__dict__ if threat else None
            }
        }
    except Exception as e:
        logger.error(f"Error processing EDR event: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/edr/endpoints/{endpoint_id}/file-event")
async def process_edr_file_event(
    endpoint_id: str,
    event_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Process file event for EDR analysis"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    try:
        edr = get_edr_system()
        
        file_event = FileEvent(
            file_path=event_data.get("file_path"),
            operation=event_data.get("operation"),
            user=event_data.get("user")
        )
        
        threat = await edr.process_file_event(endpoint_id, file_event)
        
        return {
            "success": True,
            "data": {
                "threat_detected": threat is not None,
                "threat": threat.__dict__ if threat else None
            }
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/edr/endpoints/{endpoint_id}/network-event")
async def process_edr_network_event(
    endpoint_id: str,
    event_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Process network event for EDR analysis"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    try:
        edr = get_edr_system()
        
        net_event = NetworkEvent(
            source_ip=event_data.get("source_ip"),
            dest_ip=event_data.get("dest_ip"),
            dest_port=event_data.get("dest_port"),
            protocol=event_data.get("protocol"),
            user=event_data.get("user")
        )
        
        threat = await edr.process_network_event(endpoint_id, net_event)
        
        return {
            "success": True,
            "data": {
                "threat_detected": threat is not None,
                "threat": threat.__dict__ if threat else None
            }
        }
    except Exception as e:
        logger.error(f"Error processing network event: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/edr/endpoints/{endpoint_id}")
async def get_edr_endpoint_status(
    endpoint_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get EDR endpoint status"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    edr = get_edr_system()
    status = await edr.get_endpoint_status(endpoint_id)
    
    if not status:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    return {
        "success": True,
        "data": status
    }


@router.post("/edr/endpoints/{endpoint_id}/isolate")
async def isolate_edr_endpoint(
    endpoint_id: str,
    isolation_data: dict,
    current_user: User = Depends(get_current_user)
):
    """Isolate an EDR endpoint"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    edr = get_edr_system()
    level = isolation_data.get("isolation_level", "network")
    
    success = await edr.isolate_endpoint(endpoint_id, level)
    
    if not success:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    return {
        "success": True,
        "data": {
            "endpoint_id": endpoint_id,
            "isolation_level": level,
            "status": "isolated"
        }
    }


@router.get("/edr/threats")
async def get_edr_threats(
    endpoint_id: str = None,
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(get_current_user)
):
    """Get EDR threats"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    edr = get_edr_system()
    threats = await edr.get_threats(endpoint_id)
    
    return {
        "success": True,
        "data": threats[-limit:],
        "total": len(threats)
    }


# ============================================================================
# ML Pipeline Endpoints
# ============================================================================

@router.get("/ml/retraining-status")
async def get_retraining_status(current_user: User = Depends(get_current_user)):
    """Get retraining pipeline status"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    pipeline = get_retraining_pipeline()
    status = await pipeline.get_status()
    
    return {
        "success": True,
        "data": status
    }


@router.get("/ml/model-status/{model_id}")
async def get_model_status(
    model_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get specific model status"""
    if not ML_MODELS_AVAILABLE:
        raise HTTPException(status_code=503, detail="ML models not available")
    
    pipeline = get_retraining_pipeline()
    status = await pipeline.get_model_status(model_id)
    
    return {
        "success": True,
        "data": status
    }


# ============================================================================
# Health Check
# ============================================================================

@router.get("/ml/health")
async def ml_health_check():
    """Check ML models health"""
    return {
        "success": True,
        "data": {
            "models_available": ML_MODELS_AVAILABLE,
            "soar": "✅" if ML_MODELS_AVAILABLE else "❌",
            "ueba": "✅" if ML_MODELS_AVAILABLE else "❌",
            "edr": "✅" if ML_MODELS_AVAILABLE else "❌",
            "xdr": "✅" if ML_MODELS_AVAILABLE else "❌"
        }
    }
