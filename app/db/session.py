"""
app/db/session.py
──────────────────
Async SQLAlchemy engine and session factory.
Supports both PostgreSQL (asyncpg) and SQLite (aiosqlite) via the DATABASE_URL.
"""

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.core.config import settings

# Engine kwargs differ between SQLite and PostgreSQL
connect_args = {}
engine_kwargs = {
    "echo": settings.DEBUG,
    "future": True,
}

if settings.is_sqlite:
    # SQLite requires check_same_thread=False for async use
    connect_args["check_same_thread"] = False
else:
    # PostgreSQL connection pool settings
    engine_kwargs.update(
        {
            "pool_size": 10,
            "max_overflow": 20,
            "pool_pre_ping": True,
            "pool_recycle": 3600,
        }
    )

engine = create_async_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    **engine_kwargs,
)

# Session factory – use as async context manager
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)
