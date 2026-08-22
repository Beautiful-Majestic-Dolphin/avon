"""WebAuthn challenge storage — Redis with in-memory fallback."""

from __future__ import annotations

import os
from uuid import UUID

try:
    from redis.asyncio import Redis
except ImportError:
    Redis = None  # type: ignore


class ChallengeStore:
    """One-time, short-lived, shared across replicas. Uses Redis if available, else memory."""

    def __init__(self, redis=None, ttl_seconds: int = 300) -> None:
        self._redis = redis
        self._ttl = ttl_seconds
        self._mem: dict[str, bytes] = {}

    @staticmethod
    def _key(kind: str, subject: UUID) -> str:
        return f"avon:webauthn:{kind}:{subject}"

    async def put(self, kind: str, subject: UUID, challenge: bytes) -> None:
        key = self._key(kind, subject)
        if self._redis is not None:
            try:
                await self._redis.set(key, challenge, ex=self._ttl)
                return
            except Exception:
                pass
        self._mem[key] = challenge

    async def take(self, kind: str, subject: UUID) -> bytes | None:
        key = self._key(kind, subject)
        if self._redis is not None:
            try:
                # GETDEL if available, else get+del
                try:
                    value = await self._redis.getdel(key)  # type: ignore
                except AttributeError:
                    value = await self._redis.get(key)
                    if value is not None:
                        await self._redis.delete(key)
                if value is None:
                    return self._mem.pop(key, None)
                return value if isinstance(value, bytes) else str(value).encode()
            except Exception:
                pass
        return self._mem.pop(key, None)


# Global store — lazy init with Redis if URL available
_global_store: ChallengeStore | None = None


def get_challenge_store() -> ChallengeStore:
    global _global_store
    if _global_store is None:
        redis = None
        url = (
            os.getenv("AVON_REDIS_URL")
            or os.getenv("AVON_ADMIN_REDIS_URL")
            or os.getenv("REDIS_URL")
        )
        if url and Redis is not None:
            try:
                redis = Redis.from_url(url, decode_responses=False)  # type: ignore
            except Exception:
                redis = None
        _global_store = ChallengeStore(redis=redis)
    return _global_store


async def get_challenges() -> ChallengeStore:
    return get_challenge_store()
