from typing import Any, List, Optional, Dict
from datetime import datetime, timedelta
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from app.core.auth import get_current_user
from app.db.session import get_db
from app.models.soar import SOARPlaybook, SOARExecution, ExecutionStatus, PlaybookStatus
from app.models.user import User
from app.services.ml_client import ml_client

logger = logging.getLogger(__name__)
router = APIRouter()


# ==================== Pydantic Models ====================

class PlaybookRunRequest(BaseModel):
    incident_id: Optional[str] = None
    alert_type: str = "manual_trigger"
    severity: str = "medium"
    assets: List[str] = []
    context: Dict[str, Any] = {}


# ==================== Endpoints ====================

@router.get("/soar/playbooks", response_model=dict)
async def get_soar_playbooks(
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get all SOAR playbooks"""
    # Query playbooks
    query = select(SOARPlaybook).offset(skip).limit(limit)
    result = await db.execute(query)
    playbooks = result.scalars().all()
    
    return {
        "success": True,
        "data": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "status": p.status.value,
                "actions": p.actions,
                "execution_count": p.execution_count,
                "success_rate": p.success_rate,
                "last_executed": p.last_executed.isoformat() if p.last_executed else None,
                "created_at": p.created_at.isoformat(),
            }
            for p in playbooks
        ],
        "total": len(playbooks),
    }


@router.get("/soar/playbooks/{playbook_id}", response_model=dict)
async def get_soar_playbook(
    playbook_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get a specific SOAR playbook"""
    query = select(SOARPlaybook).where(SOARPlaybook.id == playbook_id)
    result = await db.execute(query)
    playbook = result.scalar_one_or_none()
    
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    return {
        "success": True,
        "data": {
            "id": playbook.id,
            "name": playbook.name,
            "description": playbook.description,
            "status": playbook.status.value,
            "actions": playbook.actions,
            "execution_count": playbook.execution_count,
            "success_rate": playbook.success_rate,
            "last_executed": playbook.last_executed.isoformat() if playbook.last_executed else None,
            "created_at": playbook.created_at.isoformat(),
        }
    }


@router.post("/soar/playbooks/{playbook_id}/run", response_model=dict)
async def run_soar_playbook(
    playbook_id: int,
    request: PlaybookRunRequest = Body(default_factory=PlaybookRunRequest),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """
    Execute a SOAR playbook via the ML Orchestrator.
    """
    # Get the playbook
    query = select(SOARPlaybook).where(SOARPlaybook.id == playbook_id)
    result = await db.execute(query)
    playbook = result.scalar_one_or_none()
    
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    
    # Create execution record
    execution = SOARExecution(
        playbook_id=playbook_id,
        status=ExecutionStatus.running,
        started_at=datetime.utcnow()
    )
    db.add(execution)
    await db.flush()
    await db.refresh(execution)
    
    try:
        # Call ML Service SOAR Engine
        logger.info(f"Triggering SOAR playbook {playbook_id} execution {execution.id}")
        
        ml_result = await ml_client.predict(
            model_name="soar_engine",
            features={
                "incident_id": request.incident_id or f"inc-{execution.id}",
                "playbook_id": playbook_id,
                "execution_id": execution.id,
                "severity": request.severity,
                "alert_type": request.alert_type,
                "assets": request.assets,
                "context": request.context
            }
        )
        
        # Update execution status based on ML response
        execution.status = ExecutionStatus.completed
        execution.completed_at = datetime.utcnow()
        execution.actions_executed = ml_result.get("executed_actions", [])
        
        # Update playbook stats
        playbook.execution_count += 1
        playbook.last_executed = datetime.utcnow()
        # Simple success rate update logic
        playbook.success_rate = (playbook.success_rate * (playbook.execution_count - 1) + 100) / playbook.execution_count
        
        await db.commit()
        
        return {
            "success": True,
            "data": {
                "execution_id": execution.id,
                "playbook_id": playbook.id,
                "status": "completed",
                "started_at": execution.started_at.isoformat(),
                "completed_at": execution.completed_at.isoformat(),
                "actions_executed": execution.actions_executed,
                "ml_response": ml_result
            }
        }
        
    except Exception as e:
        logger.error(f"SOAR execution failed: {e}", exc_info=True)
        
        # Update execution record with error
        execution.status = ExecutionStatus.failed
        execution.completed_at = datetime.utcnow()
        execution.error_message = str(e)
        
        await db.commit()
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"SOAR execution failed: {str(e)}"
        )


@router.post("/soar/sync", response_model=dict)
async def sync_playbooks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """
    Sync playbooks from ML Service to Backend Database.
    """
    try:
        # Fetch from ML
        ml_response = await ml_client.predict(
            model_name="soar_engine",
            features={"operation": "list_playbooks"}
        )
        
        ml_playbooks = ml_response.get("playbooks", [])
        synced_count = 0
        
        for ml_pb in ml_playbooks:
            # Check if exists by name (assuming name is unique enough for now)
            query = select(SOARPlaybook).where(SOARPlaybook.name == ml_pb["name"])
            result = await db.execute(query)
            existing_pb = result.scalar_one_or_none()
            
            if existing_pb:
                # Update
                existing_pb.description = ml_pb.get("description", "")
                existing_pb.actions = len(ml_pb.get("actions", []))
                existing_pb.updated_at = datetime.utcnow()
            else:
                # Create
                new_pb = SOARPlaybook(
                    name=ml_pb["name"],
                    description=ml_pb.get("description", ""),
                    status=PlaybookStatus.active,
                    actions=len(ml_pb.get("actions", [])),
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                db.add(new_pb)
            
            synced_count += 1
            
        await db.commit()
        
        return {
            "success": True,
            "message": f"Synced {synced_count} playbooks from ML Service",
            "count": synced_count
        }
        
    except Exception as e:
        logger.error(f"Failed to sync playbooks: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Sync failed: {str(e)}"
        )


@router.get("/soar/executions/{execution_id}", response_model=dict)
async def get_execution_status(
    execution_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get status of a playbook execution"""
    query = select(SOARExecution).where(SOARExecution.id == execution_id)
    result = await db.execute(query)
    execution = result.scalar_one_or_none()
    
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
    
    return {
        "success": True,
        "data": {
            "id": execution.id,
            "playbook_id": execution.playbook_id,
            "status": execution.status.value,
            "started_at": execution.started_at.isoformat(),
            "completed_at": execution.completed_at.isoformat() if execution.completed_at else None,
            "duration_seconds": execution.duration_seconds,
            "error_message": execution.error_message,
            "actions_executed": execution.actions_executed,
        }
    }

