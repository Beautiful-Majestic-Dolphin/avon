"""Database queries for AVON Admin API."""

from datetime import datetime
from typing import Optional
from uuid import UUID

import asyncpg
import structlog

from admin_api.db.models import (
    DbDevice,
    DbPod,
    DbPolicy,
    DbUser,
    DbEnrollmentToken,
    DbTunnel,
    DbActivityLog,
)

logger = structlog.get_logger()


class DeviceQueries:
    """Database queries for devices."""

    @staticmethod
    async def list_devices(
        conn: asyncpg.Connection,
        status: Optional[str] = None,
        pod_id: Optional[UUID] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[DbDevice]:
        """List devices with optional filtering."""
        query = """
            SELECT DISTINCT d.*
            FROM devices d
            LEFT JOIN device_pods dp ON d.id = dp.device_id
            WHERE 1=1
        """
        params: list = []
        param_idx = 1

        if status:
            query += f" AND d.status = ${param_idx}"
            params.append(status)
            param_idx += 1

        if pod_id:
            query += f" AND dp.pod_id = ${param_idx}"
            params.append(pod_id)
            param_idx += 1

        query += f" ORDER BY d.created_at DESC OFFSET ${param_idx} LIMIT ${param_idx + 1}"
        params.extend([skip, limit])

        rows = await conn.fetch(query, *params)
        return [DbDevice(**dict(row)) for row in rows]

    @staticmethod
    async def get_device(conn: asyncpg.Connection, device_id: UUID) -> Optional[DbDevice]:
        """Get a device by ID."""
        row = await conn.fetchrow(
            "SELECT * FROM devices WHERE id = $1",
            device_id,
        )
        return DbDevice(**dict(row)) if row else None

    @staticmethod
    async def get_device_pods(conn: asyncpg.Connection, device_id: UUID) -> list[UUID]:
        """Get pod IDs for a device."""
        rows = await conn.fetch(
            "SELECT pod_id FROM device_pods WHERE device_id = $1",
            device_id,
        )
        return [row["pod_id"] for row in rows]

    @staticmethod
    async def update_device_status(
        conn: asyncpg.Connection,
        device_id: UUID,
        status: str,
    ) -> bool:
        """Update device status."""
        result = await conn.execute(
            """
            UPDATE devices
            SET status = $2, updated_at = NOW()
            WHERE id = $1
            """,
            device_id,
            status,
        )
        return result == "UPDATE 1"

    @staticmethod
    async def delete_device(conn: asyncpg.Connection, device_id: UUID) -> bool:
        """Delete a device."""
        async with conn.transaction():
            await conn.execute("DELETE FROM device_pods WHERE device_id = $1", device_id)
            result = await conn.execute("DELETE FROM devices WHERE id = $1", device_id)
        return result == "DELETE 1"

    @staticmethod
    async def count_devices(
        conn: asyncpg.Connection,
        status: Optional[str] = None,
    ) -> int:
        """Count devices with optional status filter."""
        if status:
            row = await conn.fetchrow(
                "SELECT COUNT(*) as count FROM devices WHERE status = $1",
                status,
            )
        else:
            row = await conn.fetchrow("SELECT COUNT(*) as count FROM devices")
        return row["count"] if row else 0

    @staticmethod
    async def get_devices_by_status(conn: asyncpg.Connection) -> dict[str, int]:
        """Get device counts grouped by status."""
        rows = await conn.fetch(
            "SELECT status, COUNT(*) as count FROM devices GROUP BY status"
        )
        return {row["status"]: row["count"] for row in rows}


class PodQueries:
    """Database queries for pods."""

    @staticmethod
    async def list_pods(
        conn: asyncpg.Connection,
        parent_id: Optional[UUID] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[DbPod]:
        """List pods with optional parent filter."""
        if parent_id is not None:
            rows = await conn.fetch(
                """
                SELECT * FROM pods
                WHERE parent_id = $1
                ORDER BY name
                OFFSET $2 LIMIT $3
                """,
                parent_id,
                skip,
                limit,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT * FROM pods
                ORDER BY name
                OFFSET $1 LIMIT $2
                """,
                skip,
                limit,
            )
        return [DbPod(**dict(row)) for row in rows]

    @staticmethod
    async def get_pod(conn: asyncpg.Connection, pod_id: UUID) -> Optional[DbPod]:
        """Get a pod by ID."""
        row = await conn.fetchrow("SELECT * FROM pods WHERE id = $1", pod_id)
        return DbPod(**dict(row)) if row else None

    @staticmethod
    async def create_pod(
        conn: asyncpg.Connection,
        name: str,
        parent_id: Optional[UUID] = None,
        description: Optional[str] = None,
    ) -> DbPod:
        """Create a new pod."""
        row = await conn.fetchrow(
            """
            INSERT INTO pods (name, parent_id, description, created_at, updated_at)
            VALUES ($1, $2, $3, NOW(), NOW())
            RETURNING *
            """,
            name,
            parent_id,
            description,
        )
        return DbPod(**dict(row))

    @staticmethod
    async def update_pod(
        conn: asyncpg.Connection,
        pod_id: UUID,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Optional[DbPod]:
        """Update a pod."""
        updates = []
        params: list = [pod_id]
        param_idx = 2

        if name is not None:
            updates.append(f"name = ${param_idx}")
            params.append(name)
            param_idx += 1

        if description is not None:
            updates.append(f"description = ${param_idx}")
            params.append(description)
            param_idx += 1

        if not updates:
            return await PodQueries.get_pod(conn, pod_id)

        updates.append("updated_at = NOW()")
        query = f"UPDATE pods SET {', '.join(updates)} WHERE id = $1 RETURNING *"
        row = await conn.fetchrow(query, *params)
        return DbPod(**dict(row)) if row else None

    @staticmethod
    async def delete_pod(conn: asyncpg.Connection, pod_id: UUID) -> bool:
        """Delete a pod."""
        result = await conn.execute("DELETE FROM pods WHERE id = $1", pod_id)
        return result == "DELETE 1"

    @staticmethod
    async def get_pod_devices(conn: asyncpg.Connection, pod_id: UUID) -> list[UUID]:
        """Get device IDs in a pod."""
        rows = await conn.fetch(
            "SELECT device_id FROM device_pods WHERE pod_id = $1",
            pod_id,
        )
        return [row["device_id"] for row in rows]

    @staticmethod
    async def add_device_to_pod(
        conn: asyncpg.Connection,
        device_id: UUID,
        pod_id: UUID,
    ) -> bool:
        """Add a device to a pod."""
        try:
            await conn.execute(
                """
                INSERT INTO device_pods (device_id, pod_id)
                VALUES ($1, $2)
                ON CONFLICT DO NOTHING
                """,
                device_id,
                pod_id,
            )
            return True
        except Exception as e:
            logger.error("failed_to_add_device_to_pod", error=str(e))
            return False

    @staticmethod
    async def remove_device_from_pod(
        conn: asyncpg.Connection,
        device_id: UUID,
        pod_id: UUID,
    ) -> bool:
        """Remove a device from a pod."""
        result = await conn.execute(
            "DELETE FROM device_pods WHERE device_id = $1 AND pod_id = $2",
            device_id,
            pod_id,
        )
        return result == "DELETE 1"

    @staticmethod
    async def count_pods(conn: asyncpg.Connection) -> int:
        """Count total pods."""
        row = await conn.fetchrow("SELECT COUNT(*) as count FROM pods")
        return row["count"] if row else 0


class PolicyQueries:
    """Database queries for policies."""

    @staticmethod
    async def list_policies(
        conn: asyncpg.Connection,
        enabled: Optional[bool] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[DbPolicy]:
        """List policies with optional filtering."""
        if enabled is not None:
            rows = await conn.fetch(
                """
                SELECT * FROM policies
                WHERE enabled = $1
                ORDER BY priority, created_at
                OFFSET $2 LIMIT $3
                """,
                enabled,
                skip,
                limit,
            )
        else:
            rows = await conn.fetch(
                """
                SELECT * FROM policies
                ORDER BY priority, created_at
                OFFSET $1 LIMIT $2
                """,
                skip,
                limit,
            )
        return [DbPolicy(**dict(row)) for row in rows]

    @staticmethod
    async def get_policy(conn: asyncpg.Connection, policy_id: UUID) -> Optional[DbPolicy]:
        """Get a policy by ID."""
        row = await conn.fetchrow("SELECT * FROM policies WHERE id = $1", policy_id)
        return DbPolicy(**dict(row)) if row else None

    @staticmethod
    async def create_policy(
        conn: asyncpg.Connection,
        name: str,
        source_pod_id: UUID,
        destination_pod_id: UUID,
        action: str,
        priority: int = 100,
        description: Optional[str] = None,
        conditions: Optional[dict] = None,
        created_by: Optional[UUID] = None,
    ) -> DbPolicy:
        """Create a new policy."""
        import json
        row = await conn.fetchrow(
            """
            INSERT INTO policies (
                name, description, source_pod_id, destination_pod_id,
                action, priority, enabled, conditions, created_by,
                created_at, updated_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8, NOW(), NOW())
            RETURNING *
            """,
            name,
            description,
            source_pod_id,
            destination_pod_id,
            action,
            priority,
            json.dumps(conditions) if conditions else None,
            created_by,
        )
        return DbPolicy(**dict(row))

    @staticmethod
    async def update_policy(
        conn: asyncpg.Connection,
        policy_id: UUID,
        name: Optional[str] = None,
        description: Optional[str] = None,
        action: Optional[str] = None,
        priority: Optional[int] = None,
        enabled: Optional[bool] = None,
        conditions: Optional[dict] = None,
    ) -> Optional[DbPolicy]:
        """Update a policy."""
        import json
        updates = []
        params: list = [policy_id]
        param_idx = 2

        if name is not None:
            updates.append(f"name = ${param_idx}")
            params.append(name)
            param_idx += 1

        if description is not None:
            updates.append(f"description = ${param_idx}")
            params.append(description)
            param_idx += 1

        if action is not None:
            updates.append(f"action = ${param_idx}")
            params.append(action)
            param_idx += 1

        if priority is not None:
            updates.append(f"priority = ${param_idx}")
            params.append(priority)
            param_idx += 1

        if enabled is not None:
            updates.append(f"enabled = ${param_idx}")
            params.append(enabled)
            param_idx += 1

        if conditions is not None:
            updates.append(f"conditions = ${param_idx}")
            params.append(json.dumps(conditions))
            param_idx += 1

        if not updates:
            return await PolicyQueries.get_policy(conn, policy_id)

        updates.append("updated_at = NOW()")
        query = f"UPDATE policies SET {', '.join(updates)} WHERE id = $1 RETURNING *"
        row = await conn.fetchrow(query, *params)
        return DbPolicy(**dict(row)) if row else None

    @staticmethod
    async def delete_policy(conn: asyncpg.Connection, policy_id: UUID) -> bool:
        """Delete a policy."""
        result = await conn.execute("DELETE FROM policies WHERE id = $1", policy_id)
        return result == "DELETE 1"

    @staticmethod
    async def count_policies(
        conn: asyncpg.Connection,
        enabled: Optional[bool] = None,
    ) -> int:
        """Count policies with optional enabled filter."""
        if enabled is not None:
            row = await conn.fetchrow(
                "SELECT COUNT(*) as count FROM policies WHERE enabled = $1",
                enabled,
            )
        else:
            row = await conn.fetchrow("SELECT COUNT(*) as count FROM policies")
        return row["count"] if row else 0


class UserQueries:
    """Database queries for users."""

    @staticmethod
    async def get_user_by_email(conn: asyncpg.Connection, email: str) -> Optional[DbUser]:
        """Get a user by email."""
        row = await conn.fetchrow("SELECT * FROM users WHERE email = $1", email)
        return DbUser(**dict(row)) if row else None

    @staticmethod
    async def get_user(conn: asyncpg.Connection, user_id: UUID) -> Optional[DbUser]:
        """Get a user by ID."""
        row = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
        return DbUser(**dict(row)) if row else None

    @staticmethod
    async def create_user(
        conn: asyncpg.Connection,
        email: str,
        hashed_password: str,
        full_name: Optional[str] = None,
        is_admin: bool = False,
    ) -> DbUser:
        """Create a new user."""
        row = await conn.fetchrow(
            """
            INSERT INTO users (email, hashed_password, full_name, is_admin, created_at, updated_at)
            VALUES ($1, $2, $3, $4, NOW(), NOW())
            RETURNING *
            """,
            email,
            hashed_password,
            full_name,
            is_admin,
        )
        return DbUser(**dict(row))

    @staticmethod
    async def update_last_login(conn: asyncpg.Connection, user_id: UUID) -> None:
        """Update user's last login timestamp."""
        await conn.execute(
            "UPDATE users SET last_login_at = NOW() WHERE id = $1",
            user_id,
        )

    @staticmethod
    async def list_users(
        conn: asyncpg.Connection,
        skip: int = 0,
        limit: int = 100,
    ) -> list[DbUser]:
        """List all users."""
        rows = await conn.fetch(
            """
            SELECT * FROM users
            ORDER BY created_at DESC
            OFFSET $1 LIMIT $2
            """,
            skip,
            limit,
        )
        return [DbUser(**dict(row)) for row in rows]


class EnrollmentQueries:
    """Database queries for enrollment tokens."""

    @staticmethod
    async def create_enrollment_token(
        conn: asyncpg.Connection,
        token: str,
        device_name: str,
        device_type: str,
        assigned_pods: list[UUID],
        expires_at: datetime,
        created_by: UUID,
    ) -> DbEnrollmentToken:
        """Create a new enrollment token."""
        import json
        row = await conn.fetchrow(
            """
            INSERT INTO enrollment_tokens (
                token, device_name, device_type, assigned_pods,
                expires_at, created_by, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            RETURNING *
            """,
            token,
            device_name,
            device_type,
            json.dumps([str(p) for p in assigned_pods]),
            expires_at,
            created_by,
        )
        return DbEnrollmentToken(**dict(row))

    @staticmethod
    async def get_enrollment_token(
        conn: asyncpg.Connection,
        token: str,
    ) -> Optional[DbEnrollmentToken]:
        """Get an enrollment token."""
        row = await conn.fetchrow(
            "SELECT * FROM enrollment_tokens WHERE token = $1",
            token,
        )
        return DbEnrollmentToken(**dict(row)) if row else None

    @staticmethod
    async def consume_enrollment_token(
        conn: asyncpg.Connection,
        token: str,
        device_id: UUID,
    ) -> bool:
        """Mark an enrollment token as consumed."""
        result = await conn.execute(
            """
            UPDATE enrollment_tokens
            SET consumed_at = NOW(), device_id = $2
            WHERE token = $1 AND consumed_at IS NULL
            """,
            token,
            device_id,
        )
        return result == "UPDATE 1"


class TunnelQueries:
    """Database queries for tunnels."""

    @staticmethod
    async def list_tunnels(
        conn: asyncpg.Connection,
        status: Optional[str] = None,
        device_id: Optional[UUID] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[DbTunnel]:
        """List tunnels with optional filtering."""
        query = "SELECT * FROM tunnels WHERE 1=1"
        params: list = []
        param_idx = 1

        if status:
            query += f" AND status = ${param_idx}"
            params.append(status)
            param_idx += 1

        if device_id:
            query += f" AND (source_device_id = ${param_idx} OR destination_device_id = ${param_idx})"
            params.append(device_id)
            param_idx += 1

        query += f" ORDER BY created_at DESC OFFSET ${param_idx} LIMIT ${param_idx + 1}"
        params.extend([skip, limit])

        rows = await conn.fetch(query, *params)
        return [DbTunnel(**dict(row)) for row in rows]

    @staticmethod
    async def get_tunnel(conn: asyncpg.Connection, tunnel_id: UUID) -> Optional[DbTunnel]:
        """Get a tunnel by ID."""
        row = await conn.fetchrow("SELECT * FROM tunnels WHERE id = $1", tunnel_id)
        return DbTunnel(**dict(row)) if row else None

    @staticmethod
    async def count_tunnels(
        conn: asyncpg.Connection,
        status: Optional[str] = None,
    ) -> int:
        """Count tunnels with optional status filter."""
        if status:
            row = await conn.fetchrow(
                "SELECT COUNT(*) as count FROM tunnels WHERE status = $1",
                status,
            )
        else:
            row = await conn.fetchrow("SELECT COUNT(*) as count FROM tunnels")
        return row["count"] if row else 0

    @staticmethod
    async def get_tunnel_stats(conn: asyncpg.Connection) -> dict:
        """Get tunnel statistics."""
        rows = await conn.fetch(
            "SELECT status, COUNT(*) as count FROM tunnels GROUP BY status"
        )
        stats = {row["status"]: row["count"] for row in rows}
        
        total_bytes = await conn.fetchrow(
            "SELECT COALESCE(SUM(bytes_sent), 0) as sent, COALESCE(SUM(bytes_received), 0) as received FROM tunnels"
        )
        
        return {
            "by_status": stats,
            "total_bytes_sent": total_bytes["sent"] if total_bytes else 0,
            "total_bytes_received": total_bytes["received"] if total_bytes else 0,
        }


class ActivityQueries:
    """Database queries for activity logs."""

    @staticmethod
    async def log_activity(
        conn: asyncpg.Connection,
        event_type: str,
        actor_id: Optional[UUID] = None,
        actor_type: str = "system",
        target_id: Optional[UUID] = None,
        target_type: Optional[str] = None,
        details: Optional[dict] = None,
        ip_address: Optional[str] = None,
    ) -> DbActivityLog:
        """Log an activity event."""
        import json
        row = await conn.fetchrow(
            """
            INSERT INTO activity_logs (
                event_type, actor_id, actor_type, target_id, target_type,
                details, ip_address, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            RETURNING *
            """,
            event_type,
            actor_id,
            actor_type,
            target_id,
            target_type,
            json.dumps(details) if details else None,
            ip_address,
        )
        return DbActivityLog(**dict(row))

    @staticmethod
    async def get_recent_activity(
        conn: asyncpg.Connection,
        hours: int = 24,
        limit: int = 100,
    ) -> list[DbActivityLog]:
        """Get recent activity logs."""
        rows = await conn.fetch(
            """
            SELECT * FROM activity_logs
            WHERE created_at > NOW() - INTERVAL '1 hour' * $1
            ORDER BY created_at DESC
            LIMIT $2
            """,
            hours,
            limit,
        )
        return [DbActivityLog(**dict(row)) for row in rows]
