"""
Pydantic schemas for notifications.
"""

from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from enum import Enum


class NotificationType(str, Enum):
    """Notification type."""
    THREAT = "threat"
    VULNERABILITY = "vulnerability"
    ALERT = "alert"
    SYSTEM = "system"
    INFO = "info"


class NotificationSeverity(str, Enum):
    """Notification severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class NotificationResponse(BaseModel):
    """Notification response schema."""
    id: str
    user_id: str
    title: str
    message: str
    type: str
    severity: str
    read: bool
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    action_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class NotificationCreate(BaseModel):
    """Create notification schema."""
    title: str
    message: str
    type: NotificationType = NotificationType.INFO
    severity: NotificationSeverity = NotificationSeverity.INFO
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    action_url: Optional[str] = None


class NotificationListResponse(BaseModel):
    """Notification list response."""
    notifications: List[NotificationResponse]
    total: int
    unread_count: int
    limit: int
    offset: int


class NotificationPreferenceResponse(BaseModel):
    """Notification preference response."""
    id: str
    user_id: str
    email_enabled: bool
    push_enabled: bool
    threat_notifications: bool
    vulnerability_notifications: bool
    alert_notifications: bool
    system_notifications: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class NotificationPreferenceUpdate(BaseModel):
    """Update notification preferences schema."""
    email_enabled: Optional[bool] = None
    push_enabled: Optional[bool] = None
    threat_notifications: Optional[bool] = None
    vulnerability_notifications: Optional[bool] = None
    alert_notifications: Optional[bool] = None
    system_notifications: Optional[bool] = None
