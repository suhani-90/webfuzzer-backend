"""
app/core/config.py
──────────────────
Centralized application settings loaded from environment variables.
Uses pydantic-settings for type-safe configuration with validation.
"""

from functools import lru_cache
from typing import List, Optional

from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All application settings. Values are read from .env file or env vars."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Application ────────────────────────────────────────────────────────────
    APP_NAME: str = "SmartFuzz"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENVIRONMENT: str = "development"
    API_V1_PREFIX: str = "/api/v1"

    # ── CORS ───────────────────────────────────────────────────────────────────
    FRONTEND_URL: str = "http://localhost:3000"
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
    ]

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v

    # ── Database ───────────────────────────────────────────────────────────────
    DATABASE_URL: str = "sqlite+aiosqlite:///./smartfuzz.db"

    # ── Redis / Celery ─────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"

    # ── Authentication ─────────────────────────────────────────────────────────
    SECRET_KEY: str = "change-this-secret-key-in-production-minimum-32-chars!!"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── Gemini AI ──────────────────────────────────────────────────────────────
    GEMINI_API_KEY: str = ""
    GEMINI_MODEL: str = "gemini-1.5-flash"
    GEMINI_MAX_TOKENS: int = 2048
    GEMINI_TEMPERATURE: float = 0.4

    # ── Fuzzing Engine ─────────────────────────────────────────────────────────
    MAX_CONCURRENT_REQUESTS: int = 10
    REQUEST_TIMEOUT_SECONDS: int = 10
    DEFAULT_RATE_LIMIT_RPS: float = 5.0  # requests per second per scan
    MAX_CRAWL_DEPTH: int = 3
    MAX_URLS_PER_SCAN: int = 100
    MAX_PAYLOADS_PER_PARAM: int = 30

    # ── Security ───────────────────────────────────────────────────────────────
    MAX_REQUEST_SIZE_MB: int = 10

    # ── Logging ────────────────────────────────────────────────────────────────
    LOG_LEVEL: str = "INFO"

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_sqlite(self) -> bool:
        return "sqlite" in self.DATABASE_URL


@lru_cache()
def get_settings() -> Settings:
    """Return cached settings instance (singleton)."""
    return Settings()


# Module-level convenience alias
settings = get_settings()
