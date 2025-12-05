from typing import Any, List, Optional
import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from datetime import datetime

from app.core.auth import get_current_user
from app.db.session import get_db
from app.models.alert import Alert
from app.models.user import User
from app.services.ml_client import ml_client

logger = logging.getLogger(__name__)
router = APIRouter()


class AlertSchema(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    timestamp: datetime
    resolved: bool
    source: str


@router.get("/", response_model=List[AlertSchema])
async def read_alerts(
    db: AsyncSession = Depends(get_db),
    skip: int = 0,
    limit: int = 100,
    active_only: bool = True,
    current_user: User = Depends(get_current_user),
) -> Any:
    """
    Retrieve alerts from both Backend DB and ML Service.
    """
    combined_alerts = []
    
    # 1. Fetch from Backend DB (Placeholder for now as DB model might be empty)
    try:
        # query = select(Alert).offset(skip).limit(limit)
        # result = await db.execute(query)
        # db_alerts = result.scalars().all()
        # for a in db_alerts:
        #     combined_alerts.append(AlertSchema(
        #         id=str(a.id),
        #         title=a.title,
        #         description=a.description,
        #         severity=a.severity.value,
        #         timestamp=a.created_at,
        #         resolved=a.resolved,
        #         source="backend"
        #     ))
        pass
    except Exception as e:
        logger.error(f"Failed to fetch DB alerts: {e}")

    # 2. Fetch from ML Service
    try:
        ml_alerts = await ml_client.get_alerts(active_only=active_only)
        for a in ml_alerts:
            # Map ML alert to schema
            combined_alerts.append(AlertSchema(
                id=str(a.get("id")),
                title=a.get("title", "Unknown Alert"),
                description=a.get("description", ""),
                severity=a.get("severity", "medium"),
                timestamp=datetime.fromisoformat(a.get("timestamp")) if isinstance(a.get("timestamp"), str) else datetime.now(),
                resolved=a.get("resolved", False),
                source=a.get("source", "ml_service")
            ))
    except Exception as e:
        logger.error(f"Failed to fetch ML alerts: {e}")
        # Don't fail the whole request if ML is down, just return what we have
    
    # Sort by timestamp descending
    combined_alerts.sort(key=lambda x: x.timestamp, reverse=True)
    
    return combined_alerts[:limit]


@router.get("/{alert_id}", response_model=AlertSchema)
async def read_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Any:
    """Get a specific alert by id"""
    # Try to find in ML service first (since we just fetched them)
    # This is inefficient but works for now without a unified DB
    try:
        ml_alerts = await ml_client.get_alerts(active_only=False)
        for a in ml_alerts:
            if str(a.get("id")) == alert_id:
                return AlertSchema(
                    id=str(a.get("id")),
                    title=a.get("title"),
                    description=a.get("description"),
                    severity=a.get("severity"),
                    timestamp=datetime.fromisoformat(a.get("timestamp")),
                    resolved=a.get("resolved"),
                    source=a.get("source")
                )
    except Exception:
        pass
        
    raise HTTPException(status_code=404, detail="Alert not found")