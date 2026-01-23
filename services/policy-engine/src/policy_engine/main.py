"""AVON Policy Engine main entry point."""

import asyncio
import signal
from typing import Optional

import grpc
import structlog

from policy_engine.cache.redis_cache import PolicyCache, RedisClient
from policy_engine.config import Settings
from policy_engine.db.connection import DatabasePool
from policy_engine.db.queries import PolicyQueries
from policy_engine.engine.evaluator import PolicyEvaluator
from policy_engine.engine.pod_hierarchy import PodHierarchy

logger = structlog.get_logger()


def configure_logging(log_level: str) -> None:
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

    import logging

    logging.basicConfig(
        format="%(message)s",
        level=getattr(logging, log_level.upper(), logging.INFO),
    )


class PolicyEngineService:
    """Main service class for the Policy Engine."""

    def __init__(self, settings: Settings):
        self.settings = settings
        self.db_pool: Optional[DatabasePool] = None
        self.redis_client: Optional[RedisClient] = None
        self.server: Optional[grpc.aio.Server] = None
        self._shutdown_event = asyncio.Event()

    async def start(self) -> None:
        """Start the policy engine service."""
        logger.info("AVON Policy Engine starting...")

        self.db_pool = DatabasePool(self.settings.database_url)
        await self.db_pool.connect()

        self.redis_client = RedisClient(self.settings.redis_url)
        await self.redis_client.connect()

        queries = PolicyQueries(self.db_pool.pool)
        cache = PolicyCache(self.redis_client, self.settings.cache_ttl_seconds)

        evaluator = PolicyEvaluator(queries, cache, self.settings)
        pod_hierarchy = PodHierarchy(queries, cache)

        from policy_engine.api.grpc_service import create_grpc_server

        self.server = create_grpc_server(
            evaluator=evaluator,
            pod_hierarchy=pod_hierarchy,
            port=self.settings.grpc_port,
        )

        await self.server.start()
        logger.info(
            "AVON Policy Engine started",
            grpc_port=self.settings.grpc_port,
        )

    async def stop(self) -> None:
        """Stop the policy engine service."""
        logger.info("AVON Policy Engine stopping...")

        if self.server:
            await self.server.stop(grace=5)

        if self.redis_client:
            await self.redis_client.disconnect()

        if self.db_pool:
            await self.db_pool.disconnect()

        logger.info("AVON Policy Engine stopped")

    async def wait_for_termination(self) -> None:
        """Wait for the service to be terminated."""
        await self._shutdown_event.wait()

    def request_shutdown(self) -> None:
        """Request the service to shut down."""
        self._shutdown_event.set()


async def main() -> None:
    """Main entry point for the policy engine service."""
    settings = Settings()
    configure_logging(settings.log_level)

    service = PolicyEngineService(settings)

    loop = asyncio.get_running_loop()

    def signal_handler() -> None:
        logger.info("Received shutdown signal")
        service.request_shutdown()

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)

    try:
        await service.start()
        await service.wait_for_termination()
    except Exception as e:
        logger.error("Service failed", error=str(e))
        raise
    finally:
        await service.stop()


if __name__ == "__main__":
    asyncio.run(main())
