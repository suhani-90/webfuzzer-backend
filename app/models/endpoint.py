"""
app/models/endpoint.py
───────────────────────
Endpoints discovered by the crawler during a scan.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base

class DiscoveredEndpoint(Base):
    """A URL/form/parameter discovered by the web crawler."""

    __tablename__ = "endpoints"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    # JSON list of discovered parameter names
    parameters: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    # JSON list of discovered form field names
    forms: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    # JSON dict of response headers from this endpoint
    headers: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    content_type: Mapped[str] = mapped_column(String(255), nullable=True)
    status_code: Mapped[int] = mapped_column(nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship(
        "Scan", back_populates="endpoints"
    )  # noqa: F821

    def __repr__(self) -> str:
        return f"<Endpoint {self.method} {self.url}>"
