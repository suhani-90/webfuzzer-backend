"""
app/models/scan.py
───────────────────
Tracks a complete fuzzing scan session from start to finish.
"""

import uuid
from datetime import datetime, timezone
from enum import Enum


from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Float,
    Enum as SAEnum,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base_class import Base

class ScanStatus(str, Enum):
    """Lifecycle states of a scan."""

    PENDING = "pending"
    AI_GENERATING = "ai_generating"
    CRAWLING = "crawling"
    FUZZING = "fuzzing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    """Maps to the frontend ScanType dropdown options."""

    BASIC_FUZZING = "Basic Fuzzing"
    SQL_INJECTION = "SQL Injection Test"
    XSS_TEST = "XSS Test"
    FULL_SECURITY_SCAN = "Full Security Scan"


class Scan(Base):
    """A single scan session targeting a specific URL."""

    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("targets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Scan configuration snapshot (stored at scan creation time)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scan_type: Mapped[str] = mapped_column(
        SAEnum(ScanType), default=ScanType.FULL_SECURITY_SCAN, nullable=False
    )
    depth: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    payload_config: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Status & Progress
    status: Mapped[str] = mapped_column(
        SAEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True
    )
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Runtime Metrics
    total_requests: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    total_endpoints: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    vulnerabilities_found: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    avg_response_time_ms: Mapped[float] = mapped_column(
        Float, default=0.0, nullable=False
    )

    # Celery task tracking
    celery_task_id: Mapped[str] = mapped_column(String(255), nullable=True)
    error_message: Mapped[str] = mapped_column(String(2000), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    owner: Mapped["User"] = relationship("User", back_populates="scans")  # noqa: F821
    target: Mapped["Target"] = relationship(
        "Target", back_populates="scans"
    )  # noqa: F821
    endpoints: Mapped[list["DiscoveredEndpoint"]] = relationship(  # noqa: F821
        "DiscoveredEndpoint", back_populates="scan", cascade="all, delete-orphan"
    )
    vulnerabilities: Mapped[list["Vulnerability"]] = relationship(  # noqa: F821
        "Vulnerability", back_populates="scan", cascade="all, delete-orphan"
    )
    payloads: Mapped[list["Payload"]] = relationship(  # noqa: F821
        "Payload", back_populates="scan", cascade="all, delete-orphan"
    )
    report: Mapped["Report"] = relationship(  # noqa: F821
        "Report", back_populates="scan", uselist=False, cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} status={self.status} url={self.target_url}>"
