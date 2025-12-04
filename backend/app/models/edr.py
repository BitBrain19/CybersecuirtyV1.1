from datetime import datetime
import enum

from sqlalchemy import Column, Integer, String, Text, DateTime, Enum, ForeignKey
from sqlalchemy.orm import relationship

from app.db.session import Base


class EndpointStatus(str, enum.Enum):
    """Status of an endpoint"""
    online = "online"
    offline = "offline"
    at_risk = "at_risk"
    quarantined = "quarantined"


class AlertSeverity(str, enum.Enum):
    """Severity level of an alert"""
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AlertStatus(str, enum.Enum):
    """Status of an alert"""
    new = "new"
    investigated = "investigated"
    resolved = "resolved"
    false_positive = "false_positive"


class EDREndpoint(Base):
    """EDR Endpoint model"""
    __tablename__ = "edr_endpoints"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), nullable=False, unique=True, index=True)
    ip_address = Column(String(45), nullable=False, unique=True)  # IPv4 or IPv6
    os = Column(String(255), nullable=False)  # Operating System
    os_version = Column(String(255), nullable=True)
    agent_version = Column(String(50), nullable=True)
    status = Column(Enum(EndpointStatus), default=EndpointStatus.online)
    last_seen = Column(DateTime, nullable=True)
    risk_score = Column(Integer, default=0)  # 0-100
    total_alerts = Column(Integer, default=0)
    active_threats = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    alerts = relationship("EDRAlert", back_populates="endpoint", cascade="all, delete-orphan")


class EDRAlert(Base):
    """EDR Alert model"""
    __tablename__ = "edr_alerts"

    id = Column(Integer, primary_key=True, index=True)
    endpoint_id = Column(Integer, ForeignKey("edr_endpoints.id"), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(Enum(AlertSeverity), default=AlertSeverity.medium)
    status = Column(Enum(AlertStatus), default=AlertStatus.new)
    alert_type = Column(String(100), nullable=False)  # e.g., "malware", "suspicious_process"
    process_name = Column(String(255), nullable=True)
    process_id = Column(Integer, nullable=True)
    file_hash = Column(String(64), nullable=True)  # SHA256 hash
    detection_time = Column(DateTime, default=datetime.utcnow)
    remediation_action = Column(String(255), nullable=True)
    is_acknowledged = Column(Integer, default=0)  # 0=false, 1=true
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    endpoint = relationship("EDREndpoint", back_populates="alerts")
