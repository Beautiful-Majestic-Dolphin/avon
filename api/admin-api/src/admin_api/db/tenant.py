"""Tenant-scoped connections — RLS backstop."""

from __future__ import annotations

from collections.abc import AsyncIterator

import asyncpg
from fastapi import Depends

from admin_api.auth.dependencies import CurrentUser, get_current_user
from admin_api.db.connection import DatabasePool


async def tenant_connection(
    current: CurrentUser = Depends(get_current_user),
) -> AsyncIterator[asyncpg.Connection]:
    """Yield a connection inside a transaction with avon.tenant_id set.

    Every query is filtered by row-level security even if a handler forgets a WHERE clause.
    """
    pool = DatabasePool.get_pool()
    conn = await pool.acquire()
    tr = conn.transaction()
    await tr.start()
    try:
        await conn.execute(
            "SELECT set_config('avon.tenant_id', $1, true)",
            str(current.user.tenant_id or current.user.id),
        )
        # Fallback to tenant_id from user; if not present, use id
        yield conn
    except Exception:
        await tr.rollback()
        raise
    else:
        await tr.commit()
    finally:
        await pool.release(conn)


async def scim_tenant_connection(
    token=Depends(lambda: None),
) -> AsyncIterator[asyncpg.Connection]:
    """SCIM variant — uses token's tenant."""
    # For now, same as tenant_connection but with SCIM token
    # Placeholder: actual implementation will verify SCIM token
    pool = DatabasePool.get_pool()
    conn = await pool.acquire()
    tr = conn.transaction()
    await tr.start()
    try:
        # In SCIM, tenant is from token; fallback
        tenant_id = getattr(token, "tenant_id", None) if token else None
        if tenant_id:
            await conn.execute(
                "SELECT set_config('avon.tenant_id', $1, true)", str(tenant_id)
            )
        yield conn
    except Exception:
        await tr.rollback()
        raise
    else:
        await tr.commit()
    finally:
        await pool.release(conn)
