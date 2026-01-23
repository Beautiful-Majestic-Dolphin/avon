"""Database connection management for AVON Admin API."""

from typing import AsyncGenerator

import asyncpg
import structlog

from admin_api.config import settings

logger = structlog.get_logger()


class DatabasePool:
    """Manages the asyncpg connection pool."""

    _pool: asyncpg.Pool | None = None

    @classmethod
    async def connect(cls) -> None:
        """Create the database connection pool."""
        if cls._pool is not None:
            return

        masked_url = settings.database_url.split("@")[-1] if "@" in settings.database_url else settings.database_url
        logger.info("connecting_to_database", url=masked_url)

        cls._pool = await asyncpg.create_pool(
            settings.database_url,
            min_size=5,
            max_size=20,
        )
        logger.info("database_pool_created")

    @classmethod
    async def disconnect(cls) -> None:
        """Close the database connection pool."""
        if cls._pool is not None:
            await cls._pool.close()
            cls._pool = None
            logger.info("database_pool_closed")

    @classmethod
    async def acquire(cls) -> asyncpg.Connection:
        """Acquire a connection from the pool."""
        if cls._pool is None:
            raise RuntimeError("Database pool not initialized")
        return await cls._pool.acquire()

    @classmethod
    async def release(cls, conn: asyncpg.Connection) -> None:
        """Release a connection back to the pool."""
        if cls._pool is not None:
            await cls._pool.release(conn)

    @classmethod
    def get_pool(cls) -> asyncpg.Pool:
        """Get the connection pool."""
        if cls._pool is None:
            raise RuntimeError("Database pool not initialized")
        return cls._pool


async def get_db() -> AsyncGenerator[asyncpg.Connection, None]:
    """FastAPI dependency for database connections."""
    conn = await DatabasePool.acquire()
    try:
        yield conn
    finally:
        await DatabasePool.release(conn)
