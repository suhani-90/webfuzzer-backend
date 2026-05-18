"""
app/schemas/scan.py
────────────────────
Scan request/response schemas.
Mirrors the frontend ScanConfig, ScanLog, and ScanType types exactly.
"""

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field, field_validator

from backend.app.models.scan import ScanStatus, ScanType

# ── Request Schemas ────────────────────────────────────────────────────────────


class PayloadConfig(BaseModel):
    """Mirrors frontend payload checkboxes from NewScan.tsx."""

    sql: bool = True
    xss: bool = True
    longString: bool = False
    specialChar: bool = False
    custom: str = ""


class ScanStartRequest(BaseModel):
    """
    Payload for POST /api/v1/scans/start.
    Exactly mirrors the ScanConfig interface from the React frontend.
    """

    targetUrl: str = Field(..., description="Target URL to scan")
    scanType: ScanType = Field(ScanType.FULL_SECURITY_SCAN)
    depth: int = Field(3, ge=1, le=10, description="Scan iterations (1-10)")
    payloads: PayloadConfig = Field(default_factory=PayloadConfig)

    @field_validator("targetUrl")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("URL must start with http:// or https://")
        return v.rstrip("/")


# ── Response Schemas ───────────────────────────────────────────────────────────


class ScanLogEntry(BaseModel):
    """
    A single terminal log entry streamed to the frontend LiveScan terminal.
    Matches the ScanLog interface in types.ts exactly.
    """

    id: str
    timestamp: str  # "HH:MM:SS" formatted
    url: str
    payload: str
    status: int  # HTTP status code
    method: str  # GET | POST
    response_time_ms: Optional[float] = None


class ScanStatusResponse(BaseModel):
    """Current scan status returned from GET /api/v1/scans/{scan_id}/status."""

    id: str
    status: ScanStatus
    progress: int  # 0-100
    total_requests: int
    total_endpoints: int
    vulnerabilities_found: int
    avg_response_time_ms: float
    target_url: str
    scan_type: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    error_message: Optional[str]

    model_config = {"from_attributes": True}


class ScanCreateResponse(BaseModel):
    """Returned immediately after POST /api/v1/scans/start."""

    scan_id: str
    status: ScanStatus
    message: str


class ScanListItem(BaseModel):
    id: str
    target_url: str
    scan_type: str
    status: ScanStatus
    progress: int
    vulnerabilities_found: int
    created_at: datetime
    completed_at: Optional[datetime]

    model_config = {"from_attributes": True}
