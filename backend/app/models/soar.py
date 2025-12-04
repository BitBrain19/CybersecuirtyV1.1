from datetime import datetime
from typing import Optional
import enum

from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, Enum, ForeignKey
from sqlalchemy.orm import relationship

from app.db.session import Base


class PlaybookStatus(str, enum.Enum):
    """Status of a playbook"""
    active = "active"
    inactive = "inactive"
    archived = "archived"


class ExecutionStatus(str, enum.Enum):
    """Status of a playbook execution"""
    pending = "pending"
    running = "running"
    succeeded = "succeeded"
    failed = "failed"
    timeout = "timeout"


class SOARPlaybook(Base):
    """SOAR Playbook model"""
    __tablename__ = "soar_playbooks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    status = Column(Enum(PlaybookStatus), default=PlaybookStatus.active)
    actions = Column(Integer, default=0)  # Number of actions in playbook
    execution_count = Column(Integer, default=0)  # Total executions
    success_rate = Column(Integer, default=0)  # Percentage (0-100)
    last_executed = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    executions = relationship("SOARExecution", back_populates="playbook", cascade="all, delete-orphan")


class SOARExecution(Base):
    """SOAR Playbook Execution model"""
    __tablename__ = "soar_executions"

    id = Column(Integer, primary_key=True, index=True)
    playbook_id = Column(Integer, ForeignKey("soar_playbooks.id"), nullable=False, index=True)
    status = Column(Enum(ExecutionStatus), default=ExecutionStatus.pending)
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)
    duration_seconds = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    actions_executed = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    playbook = relationship("SOARPlaybook", back_populates="executions")
