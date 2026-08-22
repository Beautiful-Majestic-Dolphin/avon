"""Hash-chained audit log."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import UUID

import asyncpg
from fastapi import Request

GENESIS = b"\x00" * 32


def _canonical(payload: dict) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), default=str
    ).encode()


def _row_hash(prev_hash: bytes, payload: dict) -> bytes:
    return hashlib.sha256(prev_hash + _canonical(payload)).digest()


async def log_event(
    conn: asyncpg.Connection,
    tenant_id: UUID,
    *,
    actor: UUID | None,
    event: str,
    target: UUID | None = None,
    details: dict | None = None,
    request: Request | None = None,
    actor_type: str = "user",
) -> None:
    prev = await conn.fetchval(
        "SELECT hash FROM activity_logs WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1",
        tenant_id,
    )
    prev_hash = bytes(prev) if prev else GENESIS
    created_at = datetime.now(UTC)
    ip = request.client.host if request and request.client else None
    request_id = (
        request.headers.get("x-request-id") if request else None
    ) or hashlib.sha256(
        f"{tenant_id}{event}{created_at.isoformat()}".encode()
    ).hexdigest()[
        :16
    ]
    payload = {
        "tenant_id": str(tenant_id),
        "event": event,
        "actor": str(actor) if actor else None,
        "actor_type": actor_type,
        "target": str(target) if target else None,
        "details": details or {},
        "ip": ip,
        "request_id": request_id,
        "created_at": created_at.isoformat(),
    }
    await conn.execute(
        """INSERT INTO activity_logs (tenant_id, event_type, actor_id, actor_type, target_id, details, ip_address, request_id, prev_hash, hash, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)""",
        tenant_id,
        event,
        actor,
        actor_type,
        target,
        json.dumps(details or {}),
        ip,
        request_id,
        prev_hash,
        _row_hash(prev_hash, payload),
        created_at,
    )


async def verify_chain(conn: asyncpg.Connection, tenant_id: UUID) -> tuple[bool, int]:
    rows = await conn.fetch(
        """SELECT event_type, actor_id, actor_type, target_id, details, ip_address, request_id, prev_hash, hash, created_at
           FROM activity_logs WHERE tenant_id = $1 ORDER BY id""",
        tenant_id,
    )
    expected_prev = GENESIS
    for row in rows:
        details = row["details"]
        if isinstance(details, str):
            try:
                details = json.loads(details)
            except Exception:
                details = {}
        elif details is None:
            details = {}
        payload = {
            "tenant_id": str(tenant_id),
            "event": row["event_type"],
            "actor": str(row["actor_id"]) if row["actor_id"] else None,
            "actor_type": row["actor_type"],
            "target": str(row["target_id"]) if row["target_id"] else None,
            "details": details,
            "ip": str(row["ip_address"]) if row["ip_address"] else None,
            "request_id": row["request_id"],
            "created_at": row["created_at"].isoformat(),
        }
        if bytes(row["prev_hash"]) != expected_prev or bytes(row["hash"]) != _row_hash(
            expected_prev, payload
        ):
            return False, len(rows)
        expected_prev = bytes(row["hash"])
    return True, len(rows)
