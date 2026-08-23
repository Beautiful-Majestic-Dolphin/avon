"""Database queries for AVON Admin API."""

from datetime import datetime
from uuid import UUID

import asyncpg
import structlog

from admin_api.db.models import (
    DbActivityLog,
    DbDevice,
    DbEnrollmentToken,
    DbPod,
    DbPolicy,
    DbScimToken,
    DbTunnel,
    DbUser,
    DbWebAuthnCredential,
)

logger = structlog.get_logger()


class DeviceQueries:
    """Database queries for devices."""

    @staticmethod
    async def list_devices(
        conn: asyncpg.Connection,
        status: str | None = None,
        pod_id: UUID | None = None,
        skip: int = 0,
        limit: int = 100,
    ) -> list[DbDevice]:
        """List devices with optional filtering."""
        # Tenant isolation via RLS + explicit filter for superuser
        tenant_id = await conn.fetchval(
            "SELECT current_setting('avon.tenant_id', true)"
        )
        if tenant_id:
            query = """
            SELECT DISTINCT d.*
            FROM devices d
            LEFT JOIN device_pods dp ON d.id = dp.device_id
            WHERE d.tenant_id = $1::uuid
        """
            params = [tenant_id]
            param_idx = 2
        else:
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

        query += (
            f" ORDER BY d.created_at DESC OFFSET ${param_idx} LIMIT ${param_idx + 1}"
        )
        params.extend([skip, limit])

        rows = await conn.fetch(query, *params)
        return [DbDevice(**dict(row)) for row in rows]

    @staticmethod
    async def get_device(conn: asyncpg.Connection, device_id: UUID) -> DbDevice | None:
        """Get a device by ID — tenant-scoped, returns None (404) if other tenant."""
        # Try tenant-scoped first via RLS setting
        tenant_id = await conn.fetchval(
            "SELECT current_setting('avon.tenant_id', true)"
        )
        if tenant_id:
            row = await conn.fetchrow(
                "SELECT * FROM devices WHERE id = $1 AND tenant_id = $2::uuid",
                device_id,
                tenant_id,
            )
        else:
            row = await conn.fetchrow("SELECT * FROM devices WHERE id = $1", device_id)
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
            await conn.execute(
                "DELETE FROM device_pods WHERE device_id = $1", device_id
            )
            result = await conn.execute("DELETE FROM devices WHERE id = $1", device_id)
        return result == "DELETE 1"

    @staticmethod
    async def count_devices(
        conn: asyncpg.Connection,
        status: str | None = None,
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
        parent_id: UUID | None = None,
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
    async def get_pod(conn: asyncpg.Connection, pod_id: UUID) -> DbPod | None:
        """Get a pod by ID."""
        row = await conn.fetchrow("SELECT * FROM pods WHERE id = $1", pod_id)
        return DbPod(**dict(row)) if row else None

    @staticmethod
    async def create_pod(
        conn: asyncpg.Connection,
        name: str,
        parent_id: UUID | None = None,
        description: str | None = None,
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
        name: str | None = None,
        description: str | None = None,
    ) -> DbPod | None:
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

    @staticmethod
    async def get_pod_by_external_id(
        conn: asyncpg.Connection, external_id: str
    ) -> DbPod | None:
        """Get a pod by its external IdP identifier."""
        row = await conn.fetchrow(
            "SELECT * FROM pods WHERE external_id = $1", external_id
        )
        return DbPod(**dict(row)) if row else None

    @staticmethod
    async def search_pods(
        conn: asyncpg.Connection,
        column: str,
        operator: str,
        value: str,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[list[DbPod], int]:
        """Search pods with SCIM filter. Returns (pods, total_count)."""
        allowed_columns = {"name", "external_id"}
        if column not in allowed_columns:
            return [], 0

        if operator == "eq":
            where = f"{column} = $1"
            params = [value]
        elif operator == "co":
            where = f"{column} ILIKE $1"
            params = [f"%{value}%"]
        elif operator == "sw":
            where = f"{column} ILIKE $1"
            params = [f"{value}%"]
        else:
            return [], 0

        count_row = await conn.fetchrow(
            f"SELECT COUNT(*) AS total FROM pods WHERE {where}", *params
        )
        total = count_row["total"] if count_row else 0

        rows = await conn.fetch(
            f"SELECT * FROM pods WHERE {where} ORDER BY created_at OFFSET ${len(params)+1} LIMIT ${len(params)+2}",
            *params,
            offset,
            limit,
        )
        return [DbPod(**dict(row)) for row in rows], total


class PolicyQueries:
    """Database queries for policies."""

    @staticmethod
    async def list_policies(
        conn: asyncpg.Connection,
        enabled: bool | None = None,
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
    async def get_policy(conn: asyncpg.Connection, policy_id: UUID) -> DbPolicy | None:
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
        description: str | None = None,
        conditions: dict | None = None,
        created_by: UUID | None = None,
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
        name: str | None = None,
        description: str | None = None,
        action: str | None = None,
        priority: int | None = None,
        enabled: bool | None = None,
        conditions: dict | None = None,
    ) -> DbPolicy | None:
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
        enabled: bool | None = None,
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
    async def get_user_by_email(conn: asyncpg.Connection, email: str) -> DbUser | None:
        """Get a user by email (case-insensitive)."""
        row = await conn.fetchrow(
            "SELECT * FROM users WHERE lower(email) = lower($1) LIMIT 1", email
        )
        if row is None:
            return None
        d = dict(row)
        # Map role -> is_admin for compat
        if "role" in d and "is_admin" not in d:
            d["is_admin"] = d["role"] in ("owner", "admin")
        # Map password_hash -> hashed_password
        if "password_hash" in d and "hashed_password" not in d:
            d["hashed_password"] = d["password_hash"]
        return DbUser(**d)

    @staticmethod
    async def get_user(conn: asyncpg.Connection, user_id: UUID) -> DbUser | None:
        """Get a user by ID."""
        row = await conn.fetchrow("SELECT * FROM users WHERE id = $1", user_id)
        if row is None:
            return None
        d = dict(row)
        if "role" in d and "is_admin" not in d:
            d["is_admin"] = d["role"] in ("owner", "admin")
        if "password_hash" in d and "hashed_password" not in d:
            d["hashed_password"] = d["password_hash"]
        return DbUser(**d)

    @staticmethod
    async def create_user(
        conn: asyncpg.Connection,
        email: str,
        hashed_password: str,
        full_name: str | None = None,
        is_admin: bool = False,
        tenant_id: UUID | None = None,
        role: str | None = None,
    ) -> DbUser:
        """Create a new user."""
        if tenant_id is None:
            # default tenant
            tenant_id = await conn.fetchval("SELECT id FROM tenants LIMIT 1")
        if role is None:
            role = "owner" if is_admin else "viewer"
        row = await conn.fetchrow(
            """
            INSERT INTO users (tenant_id, email, password_hash, full_name, role, is_admin, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5::user_role, $6, NOW(), NOW())
            RETURNING *
            """,
            tenant_id,
            email,
            hashed_password,
            full_name,
            role,
            is_admin,
        )
        d = dict(row)
        if "role" in d and "is_admin" not in d:
            d["is_admin"] = d["role"] in ("owner", "admin")
        if "password_hash" in d and "hashed_password" not in d:
            d["hashed_password"] = d["password_hash"]
        return DbUser(**d)

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

    @staticmethod
    async def get_user_by_external_id(
        conn: asyncpg.Connection, external_id: str
    ) -> DbUser | None:
        """Get a user by their external IdP identifier."""
        row = await conn.fetchrow(
            "SELECT * FROM users WHERE external_id = $1", external_id
        )
        return DbUser(**dict(row)) if row else None

    @staticmethod
    async def search_users(
        conn: asyncpg.Connection,
        column: str,
        operator: str,
        value: str,
        offset: int = 0,
        limit: int = 100,
    ) -> tuple[list[DbUser], int]:
        """Search users with SCIM filter. Returns (users, total_count)."""
        allowed_columns = {"email", "external_id", "full_name"}
        if column not in allowed_columns:
            return [], 0

        if operator == "eq":
            where = f"{column} = $1"
            params = [value]
        elif operator == "co":
            where = f"{column} ILIKE $1"
            params = [f"%{value}%"]
        elif operator == "sw":
            where = f"{column} ILIKE $1"
            params = [f"{value}%"]
        else:
            return [], 0

        count_row = await conn.fetchrow(
            f"SELECT COUNT(*) AS total FROM users WHERE {where}", *params
        )
        total = count_row["total"] if count_row else 0

        rows = await conn.fetch(
            f"SELECT * FROM users WHERE {where} ORDER BY created_at OFFSET ${len(params)+1} LIMIT ${len(params)+2}",
            *params,
            offset,
            limit,
        )
        return [DbUser(**dict(row)) for row in rows], total

    @staticmethod
    async def count_users(conn: asyncpg.Connection) -> int:
        """Count total users."""
        row = await conn.fetchrow("SELECT COUNT(*) AS total FROM users")
        return row["total"] if row else 0

    @staticmethod
    async def update_user(
        conn: asyncpg.Connection,
        user_id: UUID,
        email: str | None = None,
        full_name: str | None = None,
        is_active: bool | None = None,
        is_admin: bool | None = None,
        external_id: str | None = None,
        managed_by: str | None = None,
        hashed_password: str | None = None,
    ) -> DbUser | None:
        """Update a user's fields. Only non-None values are updated."""
        updates = []
        params: list = [user_id]
        idx = 2

        for field, value in [
            ("email", email),
            ("full_name", full_name),
            ("is_active", is_active),
            ("is_admin", is_admin),
            ("external_id", external_id),
            ("managed_by", managed_by),
            ("hashed_password", hashed_password),
        ]:
            if value is not None:
                updates.append(f"{field} = ${idx}")
                params.append(value)
                idx += 1

        if not updates:
            return await UserQueries.get_user(conn, user_id)

        updates.append("updated_at = NOW()")
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = $1 RETURNING *"
        row = await conn.fetchrow(query, *params)
        return DbUser(**dict(row)) if row else None

    @staticmethod
    async def delete_user(conn: asyncpg.Connection, user_id: UUID) -> bool:
        """Delete a user. Returns True if deleted."""
        result = await conn.execute("DELETE FROM users WHERE id = $1", user_id)
        return result == "DELETE 1"


class EnrollmentQueries:
    """Database queries for enrollment tokens."""

    @staticmethod
    async def create_enrollment_token(
        conn: asyncpg.Connection,
        token: str,
        device_name: str,
        device_type: str = "linux",
        assigned_pods: list[UUID] | None = None,
        expires_at: datetime | None = None,
        created_by: UUID | None = None,
        max_uses: int = 1,
        require_approval: bool = False,
        tenant_id: UUID | None = None,
    ) -> DbEnrollmentToken:
        """Create a new enrollment token — stores only sha256 hash."""
        import hashlib

        if assigned_pods is None:
            assigned_pods = []
        if expires_at is None:
            from datetime import UTC, datetime, timedelta

            expires_at = datetime.now(UTC) + timedelta(hours=24)
        if tenant_id is None:
            tenant_id = await conn.fetchval("SELECT id FROM tenants LIMIT 1")
        token_hash = hashlib.sha256(token.encode()).digest()
        row = await conn.fetchrow(
            """
            INSERT INTO enrollment_tokens (
                tenant_id, token_hash, device_name, device_kind, pod_ids,
                max_uses, require_approval, expires_at, created_by, created_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
            RETURNING *
            """,
            tenant_id,
            token_hash,
            device_name,
            device_type,
            assigned_pods,
            max_uses,
            require_approval,
            expires_at,
            created_by,
        )
        return DbEnrollmentToken(**dict(row))

    @staticmethod
    async def get_enrollment_token(
        conn: asyncpg.Connection,
        token: str,
    ) -> DbEnrollmentToken | None:
        """Get an enrollment token by plaintext (hash lookup)."""
        import hashlib

        h = hashlib.sha256(token.encode()).digest()
        row = await conn.fetchrow(
            "SELECT * FROM enrollment_tokens WHERE token_hash = $1",
            h,
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
        status: str | None = None,
        device_id: UUID | None = None,
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
    async def get_tunnel(conn: asyncpg.Connection, tunnel_id: UUID) -> DbTunnel | None:
        """Get a tunnel by ID."""
        row = await conn.fetchrow("SELECT * FROM tunnels WHERE id = $1", tunnel_id)
        return DbTunnel(**dict(row)) if row else None

    @staticmethod
    async def count_tunnels(
        conn: asyncpg.Connection,
        status: str | None = None,
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
        actor_id: UUID | None = None,
        actor_type: str = "system",
        target_id: UUID | None = None,
        target_type: str | None = None,
        details: dict | None = None,
        ip_address: str | None = None,
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


class WebAuthnQueries:
    """Database queries for WebAuthn credentials."""

    @staticmethod
    async def user_has_credentials(conn: asyncpg.Connection, user_id: UUID) -> bool:
        """Check if a user has any WebAuthn credentials registered."""
        row = await conn.fetchrow(
            "SELECT EXISTS(SELECT 1 FROM webauthn_credentials WHERE user_id = $1) AS has_creds",
            user_id,
        )
        return row["has_creds"] if row else False

    @staticmethod
    async def get_credentials_for_user(
        conn: asyncpg.Connection, user_id: UUID
    ) -> list[DbWebAuthnCredential]:
        """Get all WebAuthn credentials for a user."""
        rows = await conn.fetch(
            "SELECT * FROM webauthn_credentials WHERE user_id = $1 ORDER BY created_at",
            user_id,
        )
        return [DbWebAuthnCredential(**dict(row)) for row in rows]

    @staticmethod
    async def get_credential_for_user(
        conn: asyncpg.Connection, user_id: UUID, credential_id: bytes
    ) -> DbWebAuthnCredential | None:
        """Get a credential by user and credential_id — prevents cross-user hijack."""
        row = await conn.fetchrow(
            "SELECT * FROM webauthn_credentials WHERE user_id = $1 AND credential_id = $2",
            user_id,
            credential_id,
        )
        return DbWebAuthnCredential(**dict(row)) if row else None

    @staticmethod
    async def get_credential_by_credential_id(
        conn: asyncpg.Connection, credential_id: bytes
    ) -> DbWebAuthnCredential | None:
        """Get a WebAuthn credential by its credential_id bytes."""
        row = await conn.fetchrow(
            "SELECT * FROM webauthn_credentials WHERE credential_id = $1",
            credential_id,
        )
        return DbWebAuthnCredential(**dict(row)) if row else None

    @staticmethod
    async def create_credential(
        conn: asyncpg.Connection,
        user_id: UUID,
        credential_id: bytes,
        public_key: bytes,
        sign_count: int,
        transports: list[str],
        aaguid: bytes | None,
        name: str,
    ) -> DbWebAuthnCredential:
        """Store a new WebAuthn credential."""
        row = await conn.fetchrow(
            """INSERT INTO webauthn_credentials
               (user_id, credential_id, public_key, sign_count, transports, aaguid, name)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               RETURNING *""",
            user_id,
            credential_id,
            public_key,
            sign_count,
            transports,
            aaguid,
            name,
        )
        return DbWebAuthnCredential(**dict(row))

    @staticmethod
    async def update_sign_count(
        conn: asyncpg.Connection, credential_id: bytes, new_count: int
    ) -> None:
        """Update sign_count and last_used_at after successful authentication."""
        await conn.execute(
            """UPDATE webauthn_credentials
               SET sign_count = $2, last_used_at = NOW()
               WHERE credential_id = $1""",
            credential_id,
            new_count,
        )

    @staticmethod
    async def delete_credential(
        conn: asyncpg.Connection, credential_uuid: UUID, user_id: UUID
    ) -> bool:
        """Delete a credential by its UUID. Returns True if deleted."""
        result = await conn.execute(
            "DELETE FROM webauthn_credentials WHERE id = $1 AND user_id = $2",
            credential_uuid,
            user_id,
        )
        return result == "DELETE 1"


class UserPodQueries:
    """Database queries for user-pod memberships (SCIM Group membership)."""

    @staticmethod
    async def get_user_pods(conn: asyncpg.Connection, user_id: UUID) -> list[UUID]:
        """Get all pod IDs a user belongs to."""
        rows = await conn.fetch(
            "SELECT pod_id FROM user_pods WHERE user_id = $1", user_id
        )
        return [row["pod_id"] for row in rows]

    @staticmethod
    async def get_pod_users(conn: asyncpg.Connection, pod_id: UUID) -> list[DbUser]:
        """Get all users in a pod."""
        rows = await conn.fetch(
            """SELECT u.* FROM users u
               INNER JOIN user_pods up ON u.id = up.user_id
               WHERE up.pod_id = $1
               ORDER BY u.email""",
            pod_id,
        )
        return [DbUser(**dict(row)) for row in rows]

    @staticmethod
    async def add_user_to_pod(
        conn: asyncpg.Connection, user_id: UUID, pod_id: UUID
    ) -> None:
        """Add a user to a pod. Idempotent."""
        await conn.execute(
            "INSERT INTO user_pods (user_id, pod_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            user_id,
            pod_id,
        )

    @staticmethod
    async def remove_user_from_pod(
        conn: asyncpg.Connection, user_id: UUID, pod_id: UUID
    ) -> None:
        """Remove a user from a pod."""
        await conn.execute(
            "DELETE FROM user_pods WHERE user_id = $1 AND pod_id = $2",
            user_id,
            pod_id,
        )

    @staticmethod
    async def set_pod_members(
        conn: asyncpg.Connection, pod_id: UUID, user_ids: list[UUID]
    ) -> None:
        """Replace all members of a pod with the given user IDs."""
        await conn.execute("DELETE FROM user_pods WHERE pod_id = $1", pod_id)
        for user_id in user_ids:
            await conn.execute(
                "INSERT INTO user_pods (user_id, pod_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                user_id,
                pod_id,
            )


class ScimTokenQueries:
    """Database queries for SCIM bearer tokens."""

    @staticmethod
    async def create_token(
        conn: asyncpg.Connection,
        token_hash: str,
        description: str,
        created_by: UUID,
    ) -> DbScimToken:
        """Create a new SCIM token."""
        row = await conn.fetchrow(
            """INSERT INTO scim_tokens (token_hash, description, created_by)
               VALUES ($1, $2, $3)
               RETURNING *""",
            token_hash,
            description,
            created_by,
        )
        return DbScimToken(**dict(row))

    @staticmethod
    async def get_active_by_hash(
        conn: asyncpg.Connection, token_hash: str
    ) -> DbScimToken | None:
        """Get an active SCIM token by its hash."""
        row = await conn.fetchrow(
            "SELECT * FROM scim_tokens WHERE token_hash = $1 AND is_active = TRUE",
            token_hash,
        )
        if row:
            await conn.execute(
                "UPDATE scim_tokens SET last_used_at = NOW() WHERE id = $1",
                row["id"],
            )
        return DbScimToken(**dict(row)) if row else None

    @staticmethod
    async def list_tokens(conn: asyncpg.Connection) -> list[DbScimToken]:
        """List all SCIM tokens (active and revoked)."""
        rows = await conn.fetch("SELECT * FROM scim_tokens ORDER BY created_at DESC")
        return [DbScimToken(**dict(row)) for row in rows]

    @staticmethod
    async def revoke_token(conn: asyncpg.Connection, token_id: UUID) -> bool:
        """Revoke a SCIM token. Returns True if found and revoked."""
        result = await conn.execute(
            "UPDATE scim_tokens SET is_active = FALSE WHERE id = $1",
            token_id,
        )
        return result == "UPDATE 1"
