"""Test fixtures for AVON Admin API."""

from __future__ import annotations

import asyncio
import os
import uuid

import asyncpg
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

# Set required env before importing app
os.environ.setdefault("AVON_ADMIN_JWT_SECRET_KEY", "a" * 48)
os.environ.setdefault("AVON_ADMIN_WEBAUTHN_RP_ID", "localhost")
os.environ.setdefault("AVON_ADMIN_WEBAUTHN_ORIGIN", "https://localhost")
os.environ.setdefault("AVON_ADMIN_CONTROL_URL", "https://control:50051")
os.environ.setdefault("AVON_TLS_CERT", "/tmp/cert")
os.environ.setdefault("AVON_TLS_KEY", "/tmp/key")
os.environ.setdefault("AVON_TLS_CA", "/tmp/ca")
os.environ.setdefault(
    "AVON_DATABASE_URL",
    os.getenv(
        "AVON_TEST_DATABASE_URL", "postgresql://avon:test@localhost:5432/postgres"
    ),
)
os.environ.setdefault(
    "AVON_REDIS_URL", os.getenv("AVON_TEST_REDIS_URL", "redis://localhost:6379")
)

from admin_api.auth.passwords import hash_password
from admin_api.db.connection import DatabasePool


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session")
async def db_pool():
    dsn = os.getenv("AVON_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("AVON_TEST_DATABASE_URL not set")
    try:
        base = await asyncpg.connect(dsn)
        test_db = f"avon_admin_test_{uuid.uuid4().hex[:8]}"
        await base.execute(f'CREATE DATABASE "{test_db}" TEMPLATE postgres')
        await base.close()
        test_dsn = dsn.rsplit("/", 1)[0] + f"/{test_db}"
        pool = await asyncpg.create_pool(test_dsn, min_size=1, max_size=5)
        import pathlib

        mig_dir = pathlib.Path(__file__).parents[3] / "migrations"
        for sql_file in sorted(mig_dir.glob("*.sql")):
            sql = sql_file.read_text()
            async with pool.acquire() as conn:
                await conn.execute(sql)
        yield pool
        await pool.close()
        base = await asyncpg.connect(dsn)
        await base.execute(f'DROP DATABASE "{test_db}" WITH (FORCE)')
        await base.close()
    except Exception as e:
        pytest.skip(f"DB setup failed: {e}")


@pytest_asyncio.fixture
async def db(db_pool):
    async with db_pool.acquire() as conn:
        tr = conn.transaction()
        await tr.start()
        try:
            yield conn
        finally:
            await tr.rollback()


@pytest_asyncio.fixture
async def client(db_pool):
    old_pool = DatabasePool._pool
    DatabasePool._pool = db_pool
    from admin_api.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    DatabasePool._pool = old_pool


class Owner:
    def __init__(self, email, password, user_id, tenant_id):
        self.email = email
        self.password = password
        self.id = user_id
        self.user_id = user_id
        self.tenant_id = tenant_id

    async def is_active(self):
        return True


@pytest_asyncio.fixture
async def owner(db_pool):
    async with db_pool.acquire() as db:
        email = f"owner-{uuid.uuid4().hex[:6]}@example.com"
        password = "correct-horse-battery-staple"
        hashed = hash_password(password)
        tenant_id = await db.fetchval("SELECT id FROM tenants LIMIT 1")
        if tenant_id is None:
            tenant_id = uuid.uuid4()
            await db.execute(
                "INSERT INTO tenants (id, name) VALUES ($1, $2)",
                tenant_id,
                f"test-{tenant_id}",
            )
        row = await db.fetchrow(
            "INSERT INTO users (tenant_id, email, password_hash, role, is_active, created_at, updated_at) VALUES ($1, $2, $3, 'owner'::user_role, true, NOW(), NOW()) RETURNING id",
            tenant_id,
            email,
            hashed,
        )
        user_id = row["id"]
        return Owner(email, password, user_id, tenant_id)


@pytest_asyncio.fixture
async def second_user(db_pool, owner):
    async with db_pool.acquire() as db:
        email = f"second-{uuid.uuid4().hex[:6]}@example.com"
        password = "second-password-123"
        hashed = hash_password(password)
        row = await db.fetchrow(
            "INSERT INTO users (tenant_id, email, password_hash, role, is_active, created_at, updated_at) VALUES ($1, $2, $3, 'viewer'::user_role, true, NOW(), NOW()) RETURNING id",
            owner.tenant_id,
            email,
            hashed,
        )
        return Owner(email, password, row["id"], owner.tenant_id)


@pytest_asyncio.fixture
async def other_tenant(db_pool):
    async with db_pool.acquire() as conn:
        tenant_id = uuid.uuid4()
        await conn.execute(
            "INSERT INTO tenants (id, name) VALUES ($1, $2)",
            tenant_id,
            f"other-{tenant_id.hex[:6]}",
        )
        user_id = uuid.uuid4()
        hashed = hash_password("other-pass")
        await conn.execute(
            "INSERT INTO users (id, tenant_id, email, password_hash, role, is_active, created_at, updated_at) VALUES ($1, $2, $3, 'owner'::user_role, true, NOW(), NOW())",
            user_id,
            tenant_id,
            f"other-{tenant_id.hex[:6]}@example.com",
            hashed,
        )
        device_id = uuid.uuid4()
        await conn.execute(
            "INSERT INTO devices (id, tenant_id, name, status, created_at, updated_at) VALUES ($1, $2, 'other-device', 'active'::device_status, NOW(), NOW())",
            device_id,
            tenant_id,
        )

        class OtherTenant:
            def __init__(self, tid, did, uid):
                self.tenant_id = tid
                self.device_id = did
                self.user_id = uid

            async def device_status(self):
                async with db_pool.acquire() as c:
                    row = await c.fetchrow(
                        "SELECT status::text FROM devices WHERE id = $1", self.device_id
                    )
                    return row["status"] if row else None

        yield OtherTenant(tenant_id, device_id, user_id)
        async with db_pool.acquire() as c2:
            await c2.execute("DELETE FROM devices WHERE id = $1", device_id)
            await c2.execute("DELETE FROM users WHERE id = $1", user_id)
            await c2.execute("DELETE FROM tenants WHERE id = $1", tenant_id)


class UserWithAuth:
    def __init__(self, email, password, user_id, tenant_id, role="viewer"):
        self.email = email
        self.password = password
        self.id = user_id
        self.user_id = user_id
        self.tenant_id = tenant_id
        self.role = role

    async def auth_headers(self, client):
        r = await client.post(
            "/api/v1/users/login", json={"email": self.email, "password": self.password}
        )
        if r.status_code != 200:
            return {}
        data = r.json()
        token = data.get("access_token") or data.get("mfa_token") or ""
        return {"Authorization": f"Bearer {token}"}

    async def is_active(self):
        return True


@pytest_asyncio.fixture
async def viewer(db_pool):
    async with db_pool.acquire() as db:
        tenant_id = await db.fetchval("SELECT id FROM tenants LIMIT 1")
        if tenant_id is None:
            pytest.skip("no tenant")
        email = f"viewer-{uuid.uuid4().hex[:6]}@example.com"
        password = "viewer-pass-123"
        hashed = hash_password(password)
        row = await db.fetchrow(
            "INSERT INTO users (tenant_id, email, password_hash, role, is_active, created_at, updated_at) VALUES ($1, $2, $3, 'viewer'::user_role, true, NOW(), NOW()) RETURNING id",
            tenant_id,
            email,
            hashed,
        )
        return UserWithAuth(email, password, row["id"], tenant_id, role="viewer")


@pytest_asyncio.fixture
async def admin_user(db_pool):
    async with db_pool.acquire() as db:
        tenant_id = await db.fetchval("SELECT id FROM tenants LIMIT 1")
        email = f"admin-{uuid.uuid4().hex[:6]}@example.com"
        password = "admin-pass-123"
        hashed = hash_password(password)
        row = await db.fetchrow(
            "INSERT INTO users (tenant_id, email, password_hash, role, is_active, created_at, updated_at) VALUES ($1, $2, $3, 'admin'::user_role, true, NOW(), NOW()) RETURNING id",
            tenant_id,
            email,
            hashed,
        )
        return UserWithAuth(email, password, row["id"], tenant_id, role="admin")


@pytest_asyncio.fixture
async def enrolled_device(db_pool):
    async with db_pool.acquire() as db:
        tenant_id = await db.fetchval("SELECT id FROM tenants LIMIT 1")
        device_id = uuid.uuid4()
        await db.execute(
            "INSERT INTO devices (id, tenant_id, name, status, created_at, updated_at) VALUES ($1, $2, 'enrolled', 'active'::device_status, NOW(), NOW())",
            device_id,
            tenant_id,
        )

        class Enrolled:
            def __init__(self, did):
                self.id = did

        yield Enrolled(device_id)
        import contextlib

        with contextlib.suppress(Exception):
            await db.execute("DELETE FROM devices WHERE id = $1", device_id)


@pytest_asyncio.fixture
async def db_role_check(db_pool):
    class Checker:
        async def bypassrls(self):
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user"
                )
                if row is None:
                    return False
                return bool(row["rolbypassrls"])

        async def rls_enabled(self, table):
            async with db_pool.acquire() as conn:
                row = await conn.fetchrow(
                    "SELECT relrowsecurity FROM pg_class WHERE relname = $1", table
                )
                if row is None:
                    return False
                return bool(row["relrowsecurity"])

    return Checker()


@pytest_asyncio.fixture
async def scim_token(db_pool):
    async with db_pool.acquire() as db:
        tenant_id = await db.fetchval("SELECT id FROM tenants LIMIT 1")
        owner_id = await db.fetchval(
            "SELECT id FROM users WHERE tenant_id = $1 LIMIT 1", tenant_id
        )
        token_plain = uuid.uuid4().hex
        import hashlib

        token_hash = hashlib.sha256(token_plain.encode()).digest()
        expires = await db.fetchval("SELECT NOW() + interval '1 hour'")
        await db.execute(
            "INSERT INTO scim_tokens (tenant_id, token_hash, description, scopes, expires_at, created_by) VALUES ($1, $2, 'test', '{users:read,users:write,groups:read,groups:write}', $3, $4)",
            tenant_id,
            token_hash,
            expires,
            owner_id,
        )

        class Tok:
            def __init__(self, plain, tid):
                self.plaintext = plain
                self.tenant_id = tid

        yield Tok(token_plain, tenant_id)
        await db.execute("DELETE FROM scim_tokens WHERE token_hash = $1", token_hash)


@pytest_asyncio.fixture
async def expired_scim_token(db_pool, scim_token):
    async with db_pool.acquire() as db:
        tenant_id = scim_token.tenant_id
        owner_id = await db.fetchval(
            "SELECT id FROM users WHERE tenant_id = $1 LIMIT 1", tenant_id
        )
        plain = uuid.uuid4().hex
        import hashlib

        h = hashlib.sha256(plain.encode()).digest()
        await db.execute(
            "INSERT INTO scim_tokens (tenant_id, token_hash, description, scopes, expires_at, created_by) VALUES ($1, $2, 'expired', '{users:read}', NOW() - interval '1 hour', $3)",
            tenant_id,
            h,
            owner_id,
        )

        class Tok:
            def __init__(self, p):
                self.plaintext = p

        yield Tok(plain)
        await db.execute("DELETE FROM scim_tokens WHERE token_hash = $1", h)


@pytest_asyncio.fixture
async def read_only_scim_token(db_pool, scim_token):
    async with db_pool.acquire() as db:
        tenant_id = scim_token.tenant_id
        owner_id = await db.fetchval(
            "SELECT id FROM users WHERE tenant_id = $1 LIMIT 1", tenant_id
        )
        plain = uuid.uuid4().hex
        import hashlib

        h = hashlib.sha256(plain.encode()).digest()
        await db.execute(
            "INSERT INTO scim_tokens (tenant_id, token_hash, description, scopes, expires_at, created_by) VALUES ($1, $2, 'ro', '{users:read}', NOW() + interval '1 hour', $3)",
            tenant_id,
            h,
            owner_id,
        )

        class Tok:
            def __init__(self, p):
                self.plaintext = p

        yield Tok(plain)
        await db.execute("DELETE FROM scim_tokens WHERE token_hash = $1", h)
