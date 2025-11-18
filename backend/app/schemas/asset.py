from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class AssetBase(BaseModel):
    name: str
    description: Optional[str] = None
    asset_type: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    operating_system: Optional[str] = None
    criticality: int = 1  # 1-5 scale


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    asset_type: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    operating_system: Optional[str] = None
    criticality: Optional[int] = None
    last_seen: Optional[datetime] = None


class AssetInDBBase(AssetBase):
    id: int
    created_at: datetime
    updated_at: datetime
    last_seen: Optional[datetime] = None

    class Config:
        orm_mode = True


class Asset(AssetInDBBase):
    pass


class AssetInDB(AssetInDBBase):
    pass