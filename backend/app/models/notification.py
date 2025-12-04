"""
Notification Model for persistent notification storage.
"""

from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, ForeignKey, Enum
from sqlalchemy.orm import relationship
import uuid
import enum

from app.db.session import Base


class NotificationType(str, enum.Enum):
    """Notification type enumeration."""
    THREAT = "threat"
    VULNERABILITY = "vulnerability"
    ALERT = "alert"
    SYSTEM = "system"
    INFO = "info"


class NotificationSeverity(str, enum.Enum):
    """Notification severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Notification(Base):
    """Notification model for storing user notifications."""
    
    __tablename__ = "notifications"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    title = Column(String, nullable=False)
    message = Column(String, nullable=False)
    type = Column(Enum(NotificationType), nullable=False, default=NotificationType.INFO)
    severity = Column(Enum(NotificationSeverity), nullable=False, default=NotificationSeverity.INFO)
    read = Column(Boolean, nullable=False, default=False, index=True)
    resource_id = Column(String, nullable=True)  # Link to alert, threat, etc.
    resource_type = Column(String, nullable=True)  # Type of resource (alert, threat, etc.)
    action_url = Column(String, nullable=True)  # URL to navigate to on click
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to user
    user = relationship("User", back_populates="notifications")
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "title": self.title,
            "message": self.message,
            "type": self.type.value,
            "severity": self.severity.value,
            "read": self.read,
            "resource_id": self.resource_id,
            "resource_type": self.resource_type,
            "action_url": self.action_url,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


class NotificationPreference(Base):
    """User notification preferences."""
    
    __tablename__ = "notification_preferences"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False, unique=True)
    email_enabled = Column(Boolean, nullable=False, default=True)
    push_enabled = Column(Boolean, nullable=False, default=True)
    threat_notifications = Column(Boolean, nullable=False, default=True)
    vulnerability_notifications = Column(Boolean, nullable=False, default=True)
    alert_notifications = Column(Boolean, nullable=False, default=True)
    system_notifications = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship to user
    user = relationship("User", back_populates="notification_preference")
