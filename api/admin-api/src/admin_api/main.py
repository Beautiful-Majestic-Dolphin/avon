"""AVON Admin API main entry point."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import structlog

logger = structlog.get_logger()

app = FastAPI(
    title="AVON Admin API",
    description="Administrative API for the AVON network",
    version="0.1.0",
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event() -> None:
    """Initialize services on startup."""
    logger.info("AVON Admin API starting...")
    # TODO: Initialize database connections
    # TODO: Initialize Redis connection
    logger.info("AVON Admin API initialized successfully")


@app.on_event("shutdown")
async def shutdown_event() -> None:
    """Cleanup on shutdown."""
    logger.info("AVON Admin API shutting down...")


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint."""
    return {"message": "AVON Admin API", "version": "0.1.0"}


@app.get("/health")
async def health() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "healthy"}
