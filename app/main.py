"""
app/main.py
────────────
SmartFuzz FastAPI application entry point.
Configures middleware, routers, startup/shutdown events,
CORS, rate limiting, and OpenAPI documentation.
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app.api.routes import auth, fuzz, payloads, scans, targets
from app.api.routes.payloads import reports_router
from app.api.routes.websockets import router as ws_router
from app.core.config import settings
from app.core.logging import configure_logging, get_logger
from app.db.init_db import create_tables

logger = get_logger(__name__)


# ── Rate Limiter ───────────────────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)


# ── Lifespan ───────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown events."""
    # Startup
    configure_logging()
    logger.info(
        "smartfuzz.starting", version=settings.APP_VERSION, env=settings.ENVIRONMENT
    )

    # Create DB tables (dev mode; production uses Alembic)
    await create_tables()
    logger.info("smartfuzz.ready")

    yield  # Application runs here

    # Shutdown
    logger.info("smartfuzz.shutdown")


# ── Application Factory ────────────────────────────────────────────────────────
def create_app() -> FastAPI:
    """Create and configure the FastAPI application instance."""
    app = FastAPI(
        title="SmartFuzz API",
        description=(
            "## AI-Driven Intelligent Web Fuzzer\n\n"
            "Backend API for SmartFuzz — a final year project that performs "
            "AI-guided web application security testing using Google Gemini.\n\n"
            "### Features\n"
            "- 🤖 **AI Payload Synthesis** — Gemini generates context-aware attack vectors\n"
            "- 🕷️ **Intelligent Crawling** — async BFS crawler discovers all endpoints\n"
            "- ⚡ **Adaptive Fuzzing** — parallel injection engine with real-time detection\n"
            "- 📊 **Live Dashboard** — WebSocket streaming of scan progress\n"
            "- 📄 **Audit Reports** — JSON + PDF reports with AI remediation advice\n\n"
            "### Authentication\n"
            "All endpoints (except `/auth/register` and `/auth/login`) require a "
            "JWT Bearer token in the `Authorization` header."
        ),
        version=settings.APP_VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ── Rate Limiting ──────────────────────────────────────────────────────────
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # ── CORS ───────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Accept"],
        expose_headers=["Content-Disposition"],
    )

    # ── Compression ────────────────────────────────────────────────────────────
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # ── Security Headers Middleware ────────────────────────────────────────────
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    # ── Request Size Limit ─────────────────────────────────────────────────────
    @app.middleware("http")
    async def limit_request_size(request: Request, call_next):
        max_bytes = settings.MAX_REQUEST_SIZE_MB * 1024 * 1024
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > max_bytes:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={
                    "detail": f"Request body too large. Max {settings.MAX_REQUEST_SIZE_MB}MB."
                },
            )
        return await call_next(request)

    # ── API Routers ────────────────────────────────────────────────────────────
    api_prefix = settings.API_V1_PREFIX

    app.include_router(auth.router, prefix=api_prefix)
    app.include_router(targets.router, prefix=api_prefix)
    app.include_router(scans.router, prefix=api_prefix)
    app.include_router(fuzz.router, prefix=api_prefix)
    app.include_router(payloads.router, prefix=api_prefix)
    app.include_router(reports_router, prefix=api_prefix)

    # WebSocket routes (no /api/v1 prefix — standard WS path)
    app.include_router(ws_router)

    # ── Health & Root Endpoints ────────────────────────────────────────────────
    @app.get("/", tags=["Health"], summary="Root endpoint")
    async def root():
        return {
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "status": "operational",
            "docs": "/docs",
        }

    @app.get("/health", tags=["Health"], summary="Health check")
    async def health():
        return {"status": "healthy", "environment": settings.ENVIRONMENT}

    return app


# ── Application Instance ───────────────────────────────────────────────────────
app = create_app()
