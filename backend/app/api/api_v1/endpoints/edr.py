from typing import Any, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import get_current_user
from app.db.session import get_db
from app.models.edr import EDREndpoint, EDRAlert, EndpointStatus, AlertSeverity, AlertStatus
from app.models.user import User

router = APIRouter()


@router.get("/edr/endpoints", response_model=dict)
async def get_edr_endpoints(
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    status_filter: str = None,
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get all EDR endpoints"""
    query = select(EDREndpoint)
    
    if status_filter:
        try:
            endpoint_status = EndpointStatus(status_filter)
            query = query.where(EDREndpoint.status == endpoint_status)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid status filter")
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    endpoints = result.scalars().all()
    
    return {
        "success": True,
        "data": [
            {
                "id": e.id,
                "hostname": e.hostname,
                "ip_address": e.ip_address,
                "os": e.os,
                "os_version": e.os_version,
                "agent_version": e.agent_version,
                "status": e.status.value,
                "last_seen": e.last_seen.isoformat() if e.last_seen else None,
                "risk_score": e.risk_score,
                "total_alerts": e.total_alerts,
                "active_threats": e.active_threats,
                "created_at": e.created_at.isoformat(),
            }
            for e in endpoints
        ],
        "total": len(endpoints),
    }


@router.get("/edr/endpoints/{endpoint_id}", response_model=dict)
async def get_edr_endpoint(
    endpoint_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get a specific EDR endpoint"""
    query = select(EDREndpoint).where(EDREndpoint.id == endpoint_id)
    result = await db.execute(query)
    endpoint = result.scalar_one_or_none()
    
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    return {
        "success": True,
        "data": {
            "id": endpoint.id,
            "hostname": endpoint.hostname,
            "ip_address": endpoint.ip_address,
            "os": endpoint.os,
            "os_version": endpoint.os_version,
            "agent_version": endpoint.agent_version,
            "status": endpoint.status.value,
            "last_seen": endpoint.last_seen.isoformat() if endpoint.last_seen else None,
            "risk_score": endpoint.risk_score,
            "total_alerts": endpoint.total_alerts,
            "active_threats": endpoint.active_threats,
            "created_at": endpoint.created_at.isoformat(),
        }
    }


@router.get("/edr/alerts", response_model=dict)
async def get_edr_alerts(
    db: AsyncSession = Depends(get_db),
    endpoint_id: int = Query(None),
    skip: int = 0,
    limit: int = 100,
    severity: str = None,
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get EDR alerts, optionally filtered by endpoint"""
    query = select(EDRAlert)
    
    if endpoint_id:
        query = query.where(EDRAlert.endpoint_id == endpoint_id)
    
    if severity:
        try:
            alert_severity = AlertSeverity(severity)
            query = query.where(EDRAlert.severity == alert_severity)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid severity filter")
    
    query = query.offset(skip).limit(limit)
    result = await db.execute(query)
    alerts = result.scalars().all()
    
    return {
        "success": True,
        "data": [
            {
                "id": a.id,
                "endpoint_id": a.endpoint_id,
                "title": a.title,
                "description": a.description,
                "severity": a.severity.value,
                "status": a.status.value,
                "alert_type": a.alert_type,
                "process_name": a.process_name,
                "process_id": a.process_id,
                "file_hash": a.file_hash,
                "detection_time": a.detection_time.isoformat(),
                "remediation_action": a.remediation_action,
                "is_acknowledged": bool(a.is_acknowledged),
                "created_at": a.created_at.isoformat(),
            }
            for a in alerts
        ],
        "total": len(alerts),
    }


@router.get("/edr/alerts/{alert_id}", response_model=dict)
async def get_edr_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get a specific EDR alert"""
    query = select(EDRAlert).where(EDRAlert.id == alert_id)
    result = await db.execute(query)
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    return {
        "success": True,
        "data": {
            "id": alert.id,
            "endpoint_id": alert.endpoint_id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity.value,
            "status": alert.status.value,
            "alert_type": alert.alert_type,
            "process_name": alert.process_name,
            "process_id": alert.process_id,
            "file_hash": alert.file_hash,
            "detection_time": alert.detection_time.isoformat(),
            "remediation_action": alert.remediation_action,
            "is_acknowledged": bool(alert.is_acknowledged),
            "created_at": alert.created_at.isoformat(),
        }
    }


@router.post("/edr/alerts/{alert_id}/acknowledge", response_model=dict)
async def acknowledge_alert(
    alert_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Mark an alert as acknowledged"""
    query = select(EDRAlert).where(EDRAlert.id == alert_id)
    result = await db.execute(query)
    alert = result.scalar_one_or_none()
    
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.is_acknowledged = 1
    alert.status = AlertStatus.investigated
    await db.commit()
    await db.refresh(alert)
    
    return {
        "success": True,
        "data": {
            "id": alert.id,
            "is_acknowledged": bool(alert.is_acknowledged),
            "status": alert.status.value,
            "message": "Alert acknowledged",
        }
    }


@router.post("/edr/endpoints/{endpoint_id}/isolate", response_model=dict)
async def isolate_endpoint(
    endpoint_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Isolate an endpoint (network quarantine)"""
    query = select(EDREndpoint).where(EDREndpoint.id == endpoint_id)
    result = await db.execute(query)
    endpoint = result.scalar_one_or_none()
    
    if not endpoint:
        raise HTTPException(status_code=404, detail="Endpoint not found")
    
    endpoint.status = EndpointStatus.quarantined
    await db.commit()
    await db.refresh(endpoint)
    
    return {
        "success": True,
        "data": {
            "id": endpoint.id,
            "status": endpoint.status.value,
            "message": "Endpoint isolated successfully",
        }
    }
