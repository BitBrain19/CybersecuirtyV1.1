from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class AlertBase(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "medium"  # low, medium, high, critical
    status: str = "new"  # new, investigating, resolved, false_positive
    source: str
    asset_id: Optional[int] = None
    user_id: Optional[int] = None


class AlertCreate(AlertBase):
    pass


class AlertUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    user_id: Optional[int] = None
    is_read: Optional[bool] = None
    resolved_at: Optional[datetime] = None


class AlertInDBBase(AlertBase):
    id: int
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime] = None
    is_read: bool

    class Config:
        orm_mode = True


class Alert(AlertInDBBase):
    pass


class AlertInDB(AlertInDBBase):
    pass