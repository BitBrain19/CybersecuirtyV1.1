from datetime import datetime
import enum

from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Enum, ForeignKey
from sqlalchemy.orm import relationship

from app.db.session import Base


class RiskLevel(str, enum.Enum):
    """Risk level for user anomalies"""
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class AnomalyType(str, enum.Enum):
    """Types of anomalies detected"""
    failed_login = "failed_login"
    unusual_time = "unusual_time"
    impossible_travel = "impossible_travel"
    privilege_escalation = "privilege_escalation"
    data_exfiltration = "data_exfiltration"
    credential_access = "credential_access"
    other = "other"


class UEBAUser(Base):
    """UEBA User model"""
    __tablename__ = "ueba_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), nullable=False, unique=True, index=True)
    email = Column(String(255), nullable=False, unique=True, index=True)
    full_name = Column(String(255), nullable=True)
    department = Column(String(255), nullable=True)
    risk_score = Column(Float, default=0.0)  # 0-100
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.low)
    is_active = Column(Integer, default=1)  # 1=active, 0=inactive
    last_activity = Column(DateTime, nullable=True)
    anomaly_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    anomalies = relationship("UEBAAnomaly", back_populates="user", cascade="all, delete-orphan")


class UEBAAnomaly(Base):
    """UEBA Anomaly Detection model"""
    __tablename__ = "ueba_anomalies"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("ueba_users.id"), nullable=False, index=True)
    anomaly_type = Column(Enum(AnomalyType), nullable=False)
    risk_level = Column(Enum(RiskLevel), default=RiskLevel.medium)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source_ip = Column(String(45), nullable=True)  # IPv4 or IPv6
    location = Column(String(255), nullable=True)
    confidence = Column(Float, default=0.0)  # 0-1.0
    is_acknowledged = Column(Integer, default=0)  # 0=false, 1=true
    detection_time = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    user = relationship("UEBAUser", back_populates="anomalies")
