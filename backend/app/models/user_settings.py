from sqlalchemy import Column, Boolean, ForeignKey, Integer, String, JSON
from sqlalchemy.orm import relationship

from app.db.session import Base


class UserSettings(Base):
    __tablename__ = "user_settings"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    theme = Column(String, default="light")  # light, dark, system
    notification_preferences = Column(JSON, default=lambda: {
        "email": True,
        "in_app": True,
        "alert_severity_threshold": "medium"
    })
    dashboard_layout = Column(JSON, nullable=True)  # User's custom dashboard layout
    
    # Relationships
    user = relationship("User", back_populates="settings")