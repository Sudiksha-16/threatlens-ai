from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


class UserRegister(BaseModel):
    full_name: str = Field(
        ...,
        min_length=2,
        max_length=100,
    )

    email: EmailStr

    password: str = Field(
        ...,
        min_length=8,
    )

    confirm_password: str


class UserLogin(BaseModel):
    email: EmailStr
    password: str
    remember_me: Optional[bool] = False


class UserUpdateSettings(BaseModel):
    full_name: Optional[str] = Field(
        default=None,
        min_length=2,
        max_length=100,
    )

    current_password: Optional[str] = None

    new_password: Optional[str] = Field(
        default=None,
        min_length=8,
    )

    notification_alerts: Optional[bool] = None

    notification_reports: Optional[bool] = None

    scan_retention_days: Optional[int] = Field(
        default=None,
        ge=1,
        le=365,
    )


class UserResponse(BaseModel):
    id: str
    full_name: str
    email: EmailStr
    role: str = "analyst"
    created_at: datetime
    account_status: str = "active"
    notification_preferences: Optional[dict] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse