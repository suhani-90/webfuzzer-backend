"""
app/schemas/auth.py
────────────────────
Request/response schemas for authentication endpoints.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


class UserRegisterRequest(BaseModel):
    """Payload for POST /auth/register."""

    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_-]+$")
    password: str = Field(..., min_length=8, max_length=128)
    full_name: Optional[str] = Field(None, max_length=255)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")
        return v


class UserLoginRequest(BaseModel):
    """Payload for POST /auth/login. Accepts email or username."""

    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    """JWT token pair returned on login or refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshTokenRequest(BaseModel):
    """Payload for POST /auth/refresh."""

    refresh_token: str


class UserResponse(BaseModel):
    """Public user profile returned from GET /auth/me."""

    id: str
    email: str
    username: str
    full_name: Optional[str]
    is_active: bool
    is_superuser: bool
    created_at: datetime

    model_config = {"from_attributes": True}
