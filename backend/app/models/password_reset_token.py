"""
Password Reset Token Model for secure password reset flow.
"""

from datetime import datetime, timedelta
from sqlalchemy import Column, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
import uuid
import secrets

from app.db.session import Base


class PasswordResetToken(Base):
    """Model for password reset tokens."""
    
    __tablename__ = "password_reset_tokens"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    token = Column(String, unique=True, nullable=False, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    used_at = Column(DateTime, nullable=True)  # When token was used (if at all)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationship to user
    user = relationship("User", back_populates="password_reset_tokens")
    
    @staticmethod
    def generate_token():
        """Generate a secure random token."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def create(user_id: str, expiry_minutes: int = 60):
        """Create a new password reset token."""
        token = PasswordResetToken.generate_token()
        expires_at = datetime.utcnow() + timedelta(minutes=expiry_minutes)
        return PasswordResetToken(
            user_id=user_id,
            token=token,
            expires_at=expires_at
        )
    
    def is_valid(self):
        """Check if token is still valid and unused."""
        return (
            self.used_at is None and
            datetime.utcnow() < self.expires_at
        )
    
    def mark_as_used(self):
        """Mark token as used."""
        self.used_at = datetime.utcnow()
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "expires_at": self.expires_at.isoformat(),
            "used_at": self.used_at.isoformat() if self.used_at else None,
            "created_at": self.created_at.isoformat(),
            "is_valid": self.is_valid(),
        }
