"""AVON Admin API main entry point."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app

from admin_api.config import Settings, settings
from admin_api.db.connection import DatabasePool
from admin_api.routers import (
    dashboard_router,
    device_classes_router,
    devices_router,
    pods_router,
    policies_router,
    tunnels_router,
    users_router,
)
from admin_api.routers.analytics import router as analytics_router
from admin_api.routers.scim_tokens import router as scim_tokens_router
from admin_api.routers.webauthn import router as webauthn_router
from admin_api.scim.router import router as scim_router

logger = structlog.get_logger()


def configure_logging() -> None:
    """Configure structured logging."""
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    import asyncio

    configure_logging()
    # Validate settings at startup — refuse to start with short/default secret
    try:
        # Re-validate with current env
        Settings()  # type: ignore[call-arg]
    except Exception as e:
        logger.error("invalid_settings", error=str(e))
        raise RuntimeError(f"invalid settings: {e}") from e

    if "*" in settings.cors_origins:
        raise RuntimeError("cors_origins must not contain '*'")

    logger.info("avon_admin_api_starting", version="1.0.0")

    try:
        await DatabasePool.connect()
        logger.info("database_connected")
    except Exception as e:
        logger.error("database_connection_failed", error=str(e))
        raise RuntimeError(f"database unreachable: {e}") from e

    # Start analytics collector background task
    collector_task = None
    if settings.analytics_enabled:
        from admin_api.analytics.collector import collector_loop

        collector_task = asyncio.create_task(collector_loop())
        logger.info("analytics_collector_started")

    yield

    if collector_task:
        collector_task.cancel()

    await DatabasePool.disconnect()
    logger.info("avon_admin_api_shutdown")


app = FastAPI(
    title="AVON Admin API",
    description="Administration API for AVON Zero Trust Network",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url="/redoc" if settings.enable_docs else None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)

# CORS from explicit allow-list only — no wildcard
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(devices_router, prefix="/api/v1/devices", tags=["devices"])
app.include_router(pods_router, prefix="/api/v1/pods", tags=["pods"])
app.include_router(policies_router, prefix="/api/v1/policies", tags=["policies"])
app.include_router(
    device_classes_router, prefix="/api/v1/device-classes", tags=["device-classes"]
)
app.include_router(tunnels_router, prefix="/api/v1/tunnels", tags=["tunnels"])
app.include_router(users_router, prefix="/api/v1/users", tags=["users"])
app.include_router(dashboard_router, prefix="/api/v1/dashboard", tags=["dashboard"])
app.include_router(webauthn_router, prefix="/api/v1/webauthn", tags=["webauthn"])
app.include_router(analytics_router, prefix="/api/v1/analytics", tags=["analytics"])
app.include_router(
    scim_tokens_router, prefix="/api/v1/scim-tokens", tags=["scim-tokens"]
)
app.include_router(scim_router, prefix="/scim/v2", tags=["scim"])

metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)


@app.get("/")
async def root() -> dict:
    """Root endpoint."""
    return {
        "name": "AVON Admin API",
        "version": "1.0.0",
        "docs": "/docs" if settings.enable_docs else None,
    }


@app.get("/health")
async def health() -> dict:
    """Health check endpoint."""
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.now(UTC).isoformat(),
    }


@app.get("/ready")
async def ready(request: Request):
    """Readiness check endpoint — 503 when DB is down."""
    db_ready = DatabasePool._pool is not None
    # Try a simple query if pool exists
    if db_ready:
        try:
            pool = DatabasePool.get_pool()
            async with pool.acquire() as conn:
                await conn.fetchval("SELECT 1")
        except Exception:
            db_ready = False

    body = {
        "ready": db_ready,
        "database": "connected" if db_ready else "disconnected",
        "timestamp": datetime.now(UTC).isoformat(),
    }
    if not db_ready:
        return JSONResponse(status_code=503, content=body)
    return body
