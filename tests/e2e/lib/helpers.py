"""E2E Test Helper Functions

Common utilities for test setup, teardown, and assertions.
"""

import asyncio
import uuid
from typing import Any, Callable, Coroutine, Optional, TypeVar

import aiohttp
import asyncpg
import redis.asyncio as redis
from tenacity import (
    retry,
    stop_after_delay,
    wait_exponential,
    retry_if_exception_type,
)

from .config import config

T = TypeVar("T")


async def wait_for_condition(
    condition: Callable[[], Coroutine[Any, Any, bool]],
    timeout: float = 30.0,
    interval: float = 1.0,
    description: str = "condition",
) -> None:
    """Wait for an async condition to become true.

    Args:
        condition: Async function that returns True when condition is met
        timeout: Maximum time to wait in seconds
        interval: Time between checks in seconds
        description: Description for error messages

    Raises:
        TimeoutError: If condition not met within timeout
    """
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        try:
            if await condition():
                return
        except Exception:
            pass  # Ignore errors, keep waiting
        await asyncio.sleep(interval)
    raise TimeoutError(f"Timeout waiting for {description}")


async def wait_for_service(
    url: str,
    timeout: float = 60.0,
    interval: float = 2.0,
) -> None:
    """Wait for an HTTP service to become available.

    Args:
        url: Health check URL
        timeout: Maximum time to wait in seconds
        interval: Time between checks in seconds

    Raises:
        TimeoutError: If service not available within timeout
    """
    async def check():
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    return resp.status == 200
        except Exception:
            return False

    await wait_for_condition(check, timeout, interval, f"service at {url}")


def generate_test_id(prefix: str = "test") -> str:
    """Generate a unique test identifier.

    Args:
        prefix: Prefix for the identifier

    Returns:
        Unique string like "test-a1b2c3d4"
    """
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


async def cleanup_test_data(
    postgres_url: Optional[str] = None,
    redis_url: Optional[str] = None,
    test_prefix: str = "test-",
) -> None:
    """Clean up test data from databases.

    Removes devices, pods, policies, and tunnels created during tests.

    Args:
        postgres_url: PostgreSQL connection URL
        redis_url: Redis connection URL
        test_prefix: Prefix used for test entities
    """
    postgres_url = postgres_url or config.postgres_url
    redis_url = redis_url or config.redis_url

    # Clean PostgreSQL
    try:
        conn = await asyncpg.connect(postgres_url)
        try:
            # Delete test devices and related data
            await conn.execute("""
                DELETE FROM tunnels
                WHERE source_device_id IN (
                    SELECT id FROM devices WHERE name LIKE $1
                ) OR destination_device_id IN (
                    SELECT id FROM devices WHERE name LIKE $1
                )
            """, f"{test_prefix}%")

            await conn.execute("""
                DELETE FROM pod_memberships
                WHERE device_id IN (
                    SELECT id FROM devices WHERE name LIKE $1
                )
            """, f"{test_prefix}%")

            await conn.execute("""
                DELETE FROM devices WHERE name LIKE $1
            """, f"{test_prefix}%")

            await conn.execute("""
                DELETE FROM pods WHERE name LIKE $1
            """, f"{test_prefix}%")

            await conn.execute("""
                DELETE FROM policies WHERE id IN (
                    SELECT p.id FROM policies p
                    JOIN pods src ON p.source_pod_id = src.id
                    WHERE src.name LIKE $1
                )
            """, f"{test_prefix}%")

        finally:
            await conn.close()
    except Exception as e:
        print(f"Warning: PostgreSQL cleanup failed: {e}")

    # Clean Redis
    try:
        r = redis.from_url(redis_url)
        try:
            # Delete test-related keys
            async for key in r.scan_iter(f"avon:{test_prefix}*"):
                await r.delete(key)
            async for key in r.scan_iter(f"device:{test_prefix}*"):
                await r.delete(key)
            async for key in r.scan_iter(f"session:{test_prefix}*"):
                await r.delete(key)
        finally:
            await r.close()
    except Exception as e:
        print(f"Warning: Redis cleanup failed: {e}")


async def reset_test_environment(
    postgres_url: Optional[str] = None,
    redis_url: Optional[str] = None,
) -> None:
    """Reset the test environment to a clean state.

    This is more aggressive than cleanup_test_data and removes ALL data.
    Use with caution - only in isolated test environments.

    Args:
        postgres_url: PostgreSQL connection URL
        redis_url: Redis connection URL
    """
    postgres_url = postgres_url or config.postgres_url
    redis_url = redis_url or config.redis_url

    # Reset PostgreSQL (truncate all tables)
    try:
        conn = await asyncpg.connect(postgres_url)
        try:
            await conn.execute("TRUNCATE tunnels CASCADE")
            await conn.execute("TRUNCATE policies CASCADE")
            await conn.execute("TRUNCATE pod_memberships CASCADE")
            await conn.execute("TRUNCATE pods CASCADE")
            await conn.execute("TRUNCATE certificates CASCADE")
            await conn.execute("TRUNCATE enrollments CASCADE")
            await conn.execute("TRUNCATE devices CASCADE")
        finally:
            await conn.close()
    except Exception as e:
        print(f"Warning: PostgreSQL reset failed: {e}")

    # Reset Redis (flush database)
    try:
        r = redis.from_url(redis_url)
        try:
            await r.flushdb()
        finally:
            await r.close()
    except Exception as e:
        print(f"Warning: Redis reset failed: {e}")


class TestContext:
    """Context manager for test setup and teardown.

    Provides automatic cleanup of resources created during a test.
    """

    def __init__(self):
        self.devices: list[str] = []
        self.pods: list[str] = []
        self.policies: list[str] = []
        self.admin_client = None

    async def __aenter__(self) -> "TestContext":
        from .admin_client import AdminClient
        self.admin_client = AdminClient(config.admin_api_url)
        await self.admin_client.__aenter__()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        # Clean up in reverse order of creation
        if self.admin_client:
            for policy_id in reversed(self.policies):
                try:
                    await self.admin_client.delete_policy(policy_id)
                except Exception:
                    pass

            for device_id in reversed(self.devices):
                try:
                    await self.admin_client.revoke_device(device_id)
                except Exception:
                    pass

            for pod_id in reversed(self.pods):
                try:
                    await self.admin_client.delete_pod(pod_id)
                except Exception:
                    pass

            await self.admin_client.__aexit__(exc_type, exc_val, exc_tb)

    def track_device(self, device_id: str) -> None:
        """Track a device for cleanup."""
        self.devices.append(device_id)

    def track_pod(self, pod_id: str) -> None:
        """Track a pod for cleanup."""
        self.pods.append(pod_id)

    def track_policy(self, policy_id: str) -> None:
        """Track a policy for cleanup."""
        self.policies.append(policy_id)
