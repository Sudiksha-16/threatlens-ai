from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class AlertResponse(BaseModel):
    alert_id: str
    scan_id: str
    user_id: str
    title: str
    description: str
    severity: str  # Critical, High, Medium, Low
    alert_type: str
    read_status: bool
    resolution_status: bool
    created_at: datetime
    file_name: Optional[str] = None
    file_hash: Optional[str] = None

class AlertUpdate(BaseModel):
    read_status: Optional[bool] = None
    resolution_status: Optional[bool] = None
