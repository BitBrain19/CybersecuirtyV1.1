from sqlalchemy import Column, DateTime, Enum, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import relationship

from app.db.session import Base


class AssetType(str, Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    NETWORK_DEVICE = "network_device"
    IOT_DEVICE = "iot_device"
    CLOUD_RESOURCE = "cloud_resource"
    CONTAINER = "container"
    DATABASE = "database"
    APPLICATION = "application"


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    asset_type = Column(String, nullable=False)
    ip_address = Column(String, nullable=True)
    mac_address = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    operating_system = Column(String, nullable=True)
    criticality = Column(Integer, default=1)  # 1-5 scale
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, server_default=func.now(), onupdate=func.now())
    last_seen = Column(DateTime, nullable=True)
    
    # Relationships
    alerts = relationship("Alert", back_populates="asset")
    vulnerabilities = relationship("Vulnerability", back_populates="asset")