"""Pod hierarchy management for the AVON Policy Engine."""

import structlog

from policy_engine.cache.redis_cache import PolicyCache
from policy_engine.db.queries import PolicyQueries

logger = structlog.get_logger()


class PodHierarchy:
    """Manages pod hierarchy expansion and membership."""

    def __init__(self, queries: PolicyQueries, cache: PolicyCache):
        self.queries = queries
        self.cache = cache

    async def expand_pods(self, pod_ids: list[str]) -> set[str]:
        """Expand pod list to include all ancestor pods.

        For each pod in the input list, this returns the pod itself
        plus all of its parent pods up to the root.
        """
        all_pods: set[str] = set()

        for pod_id in pod_ids:
            cached = await self.cache.get_pod_hierarchy(pod_id)
            if cached is not None:
                all_pods.update(cached)
                continue

            hierarchy = await self.queries.get_pod_hierarchy(pod_id)
            await self.cache.set_pod_hierarchy(pod_id, hierarchy)
            all_pods.update(hierarchy)

        logger.debug(
            "Expanded pod hierarchy",
            input_pods=pod_ids,
            expanded_pods=list(all_pods),
        )

        return all_pods

    async def get_device_pods(self, device_id: str) -> list[str]:
        """Get all pod IDs a device belongs to, with caching."""
        cached = await self.cache.get_device_pods(device_id)
        if cached is not None:
            return cached

        pods = await self.queries.get_device_pods(device_id)
        await self.cache.set_device_pods(device_id, pods)
        return pods

    async def get_expanded_device_pods(self, device_id: str) -> set[str]:
        """Get all pods a device belongs to, including ancestor pods."""
        direct_pods = await self.get_device_pods(device_id)
        return await self.expand_pods(direct_pods)

    async def get_all_members(
        self, pod_id: str, include_children: bool = False
    ) -> set[str]:
        """Get all device IDs in a pod.

        If include_children is True, also includes devices in child pods.
        Note: This is a placeholder - full implementation would require
        additional database queries for child pod traversal.
        """
        logger.warning(
            "get_all_members not fully implemented",
            pod_id=pod_id,
            include_children=include_children,
        )
        return set()
