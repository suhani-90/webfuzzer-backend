"""
app/models/payload.py
──────────────────────
Security test payloads — both static and AI-generated — used in a scan.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base_class import Base

class Payload(Base):
    """A single fuzzing payload associated with a scan."""

    __tablename__ = "payloads"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    scan_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Payload details
    value: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # sqli | xss | rce | auth_bypass | overflow | special_char
    is_ai_generated: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="payloads")  # noqa: F821

    def __repr__(self) -> str:
        return f"<Payload category={self.category} ai={self.is_ai_generated}>"
