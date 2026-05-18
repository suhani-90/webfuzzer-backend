"""
app/models/report.py
─────────────────────
Final scan report generated after fuzzing completes.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base_class import Base

class Report(Base):
    """Generated security audit report for a completed scan."""

    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
        index=True,
    )

    # Summary statistics
    total_vulnerabilities: Mapped[int] = mapped_column(Integer, default=0)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)

    # Executive summary (AI-generated)
    executive_summary: Mapped[str] = mapped_column(Text, nullable=True)

    # Full JSON report data (for API responses)
    report_data: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # PDF file path (if generated)
    pdf_path: Mapped[str] = mapped_column(String(512), nullable=True)

    generated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="report")  # noqa: F821

    def __repr__(self) -> str:
        return f"<Report scan_id={self.scan_id} vulns={self.total_vulnerabilities}>"
