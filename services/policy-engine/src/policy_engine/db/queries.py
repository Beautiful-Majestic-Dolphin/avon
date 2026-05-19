"""Database queries for the AVON Policy Engine."""

from datetime import datetime
from typing import Optional

import asyncpg
import structlog

from policy_engine.models.policy import Policy, PolicyAction, PolicyConditions

logger = structlog.get_logger()


class PolicyQueries:
    """Database queries for policy evaluation."""

    def __init__(self, pool: asyncpg.Pool):
        self.pool = pool

    async def get_device_pods(self, device_id: str) -> list[str]:
        """Get all pod IDs a device belongs to."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT pod_id FROM device_pods
                WHERE device_id = $1
                """,
                device_id,
            )
            return [str(row["pod_id"]) for row in rows]

    async def get_pod_hierarchy(self, pod_id: str) -> list[str]:
        """Get pod and all ancestor pods using recursive CTE."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                WITH RECURSIVE pod_ancestors AS (
                    SELECT id, parent_id, 0 as depth
                    FROM pods
                    WHERE id = $1
                    
                    UNION ALL
                    
                    SELECT p.id, p.parent_id, pa.depth + 1
                    FROM pods p
                    INNER JOIN pod_ancestors pa ON p.id = pa.parent_id
                    WHERE pa.depth < 10
                )
                SELECT id FROM pod_ancestors
                """,
                pod_id,
            )
            return [str(row["id"]) for row in rows]

    async def get_matching_policies(
        self,
        source_pods: list[str],
        dest_pods: list[str],
    ) -> list[Policy]:
        """Get policies matching source and destination pod sets."""
        if not source_pods or not dest_pods:
            return []

        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT 
                    id, name, source_pod_id, destination_pod_id,
                    action, priority, enabled, conditions,
                    description, created_at, updated_at
                FROM policies
                WHERE enabled = true
                AND source_pod_id = ANY($1::uuid[])
                AND destination_pod_id = ANY($2::uuid[])
                ORDER BY priority ASC, created_at ASC
                """,
                source_pods,
                dest_pods,
            )

            policies = []
            for row in rows:
                conditions = None
                if row["conditions"]:
                    try:
                        import json

                        conditions = PolicyConditions.model_validate(
                            json.loads(row["conditions"])
                            if isinstance(row["conditions"], str)
                            else row["conditions"]
                        )
                    except Exception as e:
                        logger.warning(
                            "Failed to parse policy conditions",
                            policy_id=str(row["id"]),
                            error=str(e),
                        )

                policies.append(
                    Policy(
                        id=str(row["id"]),
                        name=row["name"],
                        source_pod_id=str(row["source_pod_id"]),
                        destination_pod_id=str(row["destination_pod_id"]),
                        action=PolicyAction(row["action"]),
                        priority=row["priority"],
                        enabled=row["enabled"],
                        conditions=conditions,
                        description=row["description"],
                        created_at=(
                            str(row["created_at"]) if row["created_at"] else None
                        ),
                        updated_at=(
                            str(row["updated_at"]) if row["updated_at"] else None
                        ),
                    )
                )

            return policies

    async def log_policy_decision(
        self,
        source_device: str,
        dest_device: str,
        action: str,
        policy_id: Optional[str],
        reason: str,
        evaluation_time_ms: float,
    ) -> None:
        """Log policy decision for audit."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO policy_decisions (
                    source_device_id, destination_device_id,
                    action, policy_id, reason, evaluation_time_ms,
                    created_at
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                """,
                source_device,
                dest_device,
                action,
                policy_id,
                reason,
                evaluation_time_ms,
                datetime.utcnow(),
            )

    async def get_device_posture(self, device_id: str) -> Optional[dict]:
        """Get device posture information."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT 
                    os_version, agent_version, firewall_enabled,
                    disk_encrypted, last_update_check
                FROM devices
                WHERE id = $1
                """,
                device_id,
            )
            if row:
                return dict(row)
            return None
