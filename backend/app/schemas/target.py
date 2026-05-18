"""
app/schemas/target.py
──────────────────────
Target management request/response schemas.
"""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, HttpUrl, field_validator


class TargetCreateRequest(BaseModel):
    url: str = Field(..., description="Target URL to fuzz")
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    scan_depth: int = Field(3, ge=1, le=10)
    rate_limit_rps: float = Field(5.0, ge=0.1, le=50.0)
    allowed_methods: List[str] = Field(default=["GET", "POST"])
    custom_headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v.rstrip("/")


class TargetResponse(BaseModel):
    id: str
    user_id: str
    url: str
    name: Optional[str]
    description: Optional[str]
    scan_depth: int
    rate_limit_rps: float
    allowed_methods: List[str]
    created_at: datetime

    model_config = {"from_attributes": True}
