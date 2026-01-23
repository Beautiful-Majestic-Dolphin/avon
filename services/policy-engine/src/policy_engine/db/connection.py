"""Database connection management for the AVON Policy Engine."""

from typing import Optional

import asyncpg
import structlog

logger = structlog.get_logger()


class DatabasePool:
    """Manages the PostgreSQL connection pool."""

    def __init__(self, database_url: str):
        self.database_url = database_url
        self._pool: Optional[asyncpg.Pool] = None

    async def connect(self) -> None:
        """Create the connection pool."""
        logger.info("Connecting to database", url=self._mask_url(self.database_url))
        self._pool = await asyncpg.create_pool(
            self.database_url,
            min_size=2,
            max_size=10,
            command_timeout=30,
        )
        logger.info("Database connection pool created")

    async def disconnect(self) -> None:
        """Close the connection pool."""
        if self._pool:
            await self._pool.close()
            self._pool = None
            logger.info("Database connection pool closed")

    @property
    def pool(self) -> asyncpg.Pool:
        """Get the connection pool."""
        if self._pool is None:
            raise RuntimeError("Database pool not initialized. Call connect() first.")
        return self._pool

    async def acquire(self) -> asyncpg.Connection:
        """Acquire a connection from the pool."""
        return await self.pool.acquire()

    async def release(self, connection: asyncpg.Connection) -> None:
        """Release a connection back to the pool."""
        await self.pool.release(connection)

    def _mask_url(self, url: str) -> str:
        """Mask sensitive parts of the database URL for logging."""
        if "@" in url:
            parts = url.split("@")
            return f"***@{parts[-1]}"
        return url
