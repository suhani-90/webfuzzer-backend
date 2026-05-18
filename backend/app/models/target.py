"""
app/models/target.py
─────────────────────
Represents a web application target configured for fuzzing.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, JSON, String, Float
from sqlalchemy.orm import Mapped, mapped_column, relationship

from backend.app.db.base_class import Base

class Target(Base):
    """A web application target URL with its scan configuration."""

    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Target details
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=True)
    description: Mapped[str] = mapped_column(String(1000), nullable=True)

    # Scan configuration
    scan_depth: Mapped[int] = mapped_column(Integer, default=3, nullable=False)
    rate_limit_rps: Mapped[float] = mapped_column(Float, default=5.0, nullable=False)
    allowed_methods: Mapped[list] = mapped_column(
        JSON, default=lambda: ["GET", "POST"], nullable=False
    )
    custom_headers: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    cookies: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    owner: Mapped["User"] = relationship("User", back_populates="targets")  # noqa: F821
    scans: Mapped[list["Scan"]] = relationship(  # noqa: F821
        "Scan", back_populates="target", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Target id={self.id} url={self.url}>"
