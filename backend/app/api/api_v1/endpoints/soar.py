from typing import Any, List
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.db.session import get_db
from app.models.soar import SOARPlaybook, SOARExecution, ExecutionStatus, PlaybookStatus
from app.models.user import User

router = APIRouter()


# Schemas (inline for simplicity)
class PlaybookBase(dict):
    pass


class PlaybookResponse(dict):
    pass


class ExecutionResponse(dict):
    pass


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
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Execute a SOAR playbook"""
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
    )
    db.add(execution)
    await db.flush()
    
    # Simulate execution (in real scenario, this would trigger async tasks)
    await db.refresh(execution)
    
    # Update playbook
    playbook.execution_count += 1
    playbook.last_executed = datetime.utcnow()
    playbook.success_rate = 85  # Simulated success rate
    
    await db.commit()
    await db.refresh(playbook)
    await db.refresh(execution)
    
    return {
        "success": True,
        "data": {
            "execution_id": execution.id,
            "playbook_id": playbook.id,
            "status": "running",
            "started_at": execution.started_at.isoformat(),
            "message": "Playbook execution started",
        }
    }


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
