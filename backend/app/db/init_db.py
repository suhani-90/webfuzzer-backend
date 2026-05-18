"""
app/db/init_db.py
──────────────────
Creates all tables on application startup (dev mode).
In production, Alembic migrations handle schema changes.
"""

from backend.app.core.logging import get_logger
from backend.app.db.base import Base
from backend.app.db.session import engine

logger = get_logger(__name__)


async def create_tables() -> None:
    """
    Create all database tables derived from Base metadata.
    Safe to call on every startup — skips existing tables.
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("database.tables_ready")


async def drop_tables() -> None:
    """Drop all tables. Used only in test teardown — never in production."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    logger.warning("database.tables_dropped")
