"""Redis caching for the AVON Policy Engine."""

import json
from typing import Optional

import redis.asyncio as redis
import structlog

from policy_engine.models.policy import Policy

logger = structlog.get_logger()


class RedisClient:
    """Redis client wrapper."""

    def __init__(self, redis_url: str):
        self.redis_url = redis_url
        self._client: Optional[redis.Redis] = None

    async def connect(self) -> None:
        """Connect to Redis."""
        logger.info("Connecting to Redis", url=self._mask_url(self.redis_url))
        self._client = redis.from_url(
            self.redis_url,
            encoding="utf-8",
            decode_responses=True,
        )
        await self._client.ping()
        logger.info("Redis connection established")

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        if self._client:
            await self._client.close()
            self._client = None
            logger.info("Redis connection closed")

    @property
    def client(self) -> redis.Redis:
        """Get the Redis client."""
        if self._client is None:
            raise RuntimeError("Redis client not initialized. Call connect() first.")
        return self._client

    def _mask_url(self, url: str) -> str:
        """Mask sensitive parts of the Redis URL for logging."""
        if "@" in url:
            parts = url.split("@")
            return f"***@{parts[-1]}"
        return url


class PolicyCache:
    """Cache for policy-related data."""

    def __init__(self, redis_client: RedisClient, ttl_seconds: int = 60):
        self.redis = redis_client
        self.ttl = ttl_seconds

    def _pod_key(self, device_id: str) -> str:
        """Generate cache key for device pods."""
        return f"avon:policy:device_pods:{device_id}"

    def _hierarchy_key(self, pod_id: str) -> str:
        """Generate cache key for pod hierarchy."""
        return f"avon:policy:pod_hierarchy:{pod_id}"

    def _policy_key(
        self, source_pods: tuple[str, ...], dest_pods: tuple[str, ...]
    ) -> str:
        """Generate cache key for matching policies."""
        source_hash = hash(source_pods)
        dest_hash = hash(dest_pods)
        return f"avon:policy:matching:{source_hash}:{dest_hash}"

    async def get_device_pods(self, device_id: str) -> Optional[list[str]]:
        """Get cached device pods."""
        try:
            data = await self.redis.client.get(self._pod_key(device_id))
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning(
                "Cache get failed", key=self._pod_key(device_id), error=str(e)
            )
        return None

    async def set_device_pods(self, device_id: str, pod_ids: list[str]) -> None:
        """Cache device pods."""
        try:
            await self.redis.client.setex(
                self._pod_key(device_id),
                self.ttl,
                json.dumps(pod_ids),
            )
        except Exception as e:
            logger.warning(
                "Cache set failed", key=self._pod_key(device_id), error=str(e)
            )

    async def get_pod_hierarchy(self, pod_id: str) -> Optional[list[str]]:
        """Get cached pod hierarchy."""
        try:
            data = await self.redis.client.get(self._hierarchy_key(pod_id))
            if data:
                return json.loads(data)
        except Exception as e:
            logger.warning(
                "Cache get failed", key=self._hierarchy_key(pod_id), error=str(e)
            )
        return None

    async def set_pod_hierarchy(self, pod_id: str, hierarchy: list[str]) -> None:
        """Cache pod hierarchy."""
        try:
            await self.redis.client.setex(
                self._hierarchy_key(pod_id),
                self.ttl * 5,
                json.dumps(hierarchy),
            )
        except Exception as e:
            logger.warning(
                "Cache set failed", key=self._hierarchy_key(pod_id), error=str(e)
            )

    async def get_matching_policies(
        self, source_pods: list[str], dest_pods: list[str]
    ) -> Optional[list[Policy]]:
        """Get cached matching policies."""
        try:
            key = self._policy_key(tuple(sorted(source_pods)), tuple(sorted(dest_pods)))
            data = await self.redis.client.get(key)
            if data:
                policies_data = json.loads(data)
                return [Policy.model_validate(p) for p in policies_data]
        except Exception as e:
            logger.warning("Cache get failed for policies", error=str(e))
        return None

    async def set_matching_policies(
        self, source_pods: list[str], dest_pods: list[str], policies: list[Policy]
    ) -> None:
        """Cache matching policies."""
        try:
            key = self._policy_key(tuple(sorted(source_pods)), tuple(sorted(dest_pods)))
            policies_data = [p.model_dump(mode="json") for p in policies]
            await self.redis.client.setex(
                key,
                self.ttl,
                json.dumps(policies_data),
            )
        except Exception as e:
            logger.warning("Cache set failed for policies", error=str(e))

    async def invalidate_device(self, device_id: str) -> None:
        """Invalidate cache for a device."""
        try:
            await self.redis.client.delete(self._pod_key(device_id))
        except Exception as e:
            logger.warning(
                "Cache invalidation failed", device_id=device_id, error=str(e)
            )

    async def invalidate_pod(self, pod_id: str) -> None:
        """Invalidate cache for a pod."""
        try:
            await self.redis.client.delete(self._hierarchy_key(pod_id))
        except Exception as e:
            logger.warning("Cache invalidation failed", pod_id=pod_id, error=str(e))
