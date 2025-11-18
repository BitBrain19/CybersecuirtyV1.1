from typing import Any, List
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.db.session import get_db
from app.models.ueba import UEBAUser, UEBAAnomaly, RiskLevel, AnomalyType
from app.models.user import User

router = APIRouter()


@router.get("/ueba/users", response_model=dict)
async def get_ueba_users(
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get all UEBA users with risk scores"""
    # Query users
    query = select(UEBAUser).offset(skip).limit(limit)
    result = await db.execute(query)
    users = result.scalars().all()
    
    return {
        "success": True,
        "data": [
            {
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "full_name": u.full_name,
                "department": u.department,
                "risk_score": u.risk_score,
                "risk_level": u.risk_level.value,
                "is_active": bool(u.is_active),
                "last_activity": u.last_activity.isoformat() if u.last_activity else None,
                "anomaly_count": u.anomaly_count,
                "created_at": u.created_at.isoformat(),
            }
            for u in users
        ],
        "total": len(users),
    }


@router.get("/ueba/users/{user_id}", response_model=dict)
async def get_ueba_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get a specific UEBA user"""
    query = select(UEBAUser).where(UEBAUser.id == user_id)
    result = await db.execute(query)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    return {
        "success": True,
        "data": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "department": user.department,
            "risk_score": user.risk_score,
            "risk_level": user.risk_level.value,
            "is_active": bool(user.is_active),
            "last_activity": user.last_activity.isoformat() if user.last_activity else None,
            "anomaly_count": user.anomaly_count,
            "created_at": user.created_at.isoformat(),
        }
    }


@router.get("/ueba/users/{user_id}/anomalies", response_model=dict)
async def get_user_anomalies(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get anomalies detected for a specific user"""
    # Verify user exists
    user_query = select(UEBAUser).where(UEBAUser.id == user_id)
    user_result = await db.execute(user_query)
    user = user_result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Get anomalies
    query = select(UEBAAnomaly).where(
        UEBAAnomaly.user_id == user_id
    ).offset(skip).limit(limit)
    result = await db.execute(query)
    anomalies = result.scalars().all()
    
    return {
        "success": True,
        "data": [
            {
                "id": a.id,
                "user_id": a.user_id,
                "anomaly_type": a.anomaly_type.value,
                "risk_level": a.risk_level.value,
                "title": a.title,
                "description": a.description,
                "source_ip": a.source_ip,
                "location": a.location,
                "confidence": a.confidence,
                "is_acknowledged": bool(a.is_acknowledged),
                "detection_time": a.detection_time.isoformat(),
                "created_at": a.created_at.isoformat(),
            }
            for a in anomalies
        ],
        "total": len(anomalies),
    }


@router.get("/ueba/anomalies", response_model=dict)
async def get_all_anomalies(
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    risk_level: str = None,
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get all anomalies across all users"""
    query = select(UEBAAnomaly)
    
    if risk_level:
        try:
            risk = RiskLevel(risk_level)
            query = query.where(UEBAAnomaly.risk_level == risk)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid risk level")
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    anomalies = result.scalars().all()
    
    return {
        "success": True,
        "data": [
            {
                "id": a.id,
                "user_id": a.user_id,
                "anomaly_type": a.anomaly_type.value,
                "risk_level": a.risk_level.value,
                "title": a.title,
                "description": a.description,
                "source_ip": a.source_ip,
                "location": a.location,
                "confidence": a.confidence,
                "is_acknowledged": bool(a.is_acknowledged),
                "detection_time": a.detection_time.isoformat(),
                "created_at": a.created_at.isoformat(),
            }
            for a in anomalies
        ],
        "total": len(anomalies),
    }


@router.post("/ueba/users/{user_id}/anomalies/{anomaly_id}/acknowledge", response_model=dict)
async def acknowledge_anomaly(
    user_id: int,
    anomaly_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Mark an anomaly as acknowledged"""
    query = select(UEBAAnomaly).where(
        UEBAAnomaly.id == anomaly_id,
        UEBAAnomaly.user_id == user_id
    )
    result = await db.execute(query)
    anomaly = result.scalar_one_or_none()
    
    if not anomaly:
        raise HTTPException(status_code=404, detail="Anomaly not found")
    
    anomaly.is_acknowledged = 1
    await db.commit()
    await db.refresh(anomaly)
    
    return {
        "success": True,
        "data": {
            "id": anomaly.id,
            "is_acknowledged": bool(anomaly.is_acknowledged),
            "message": "Anomaly acknowledged",
        }
    }
