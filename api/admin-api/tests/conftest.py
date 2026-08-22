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
    # Try to create a test DB if AVON_TEST_DATABASE_URL is set
    dsn = os.getenv("AVON_TEST_DATABASE_URL")
    if not dsn:
        pytest.skip("AVON_TEST_DATABASE_URL not set")
    try:
        # Create ephemeral DB
        base = await asyncpg.connect(dsn)
        test_db = f"avon_admin_test_{uuid.uuid4().hex[:8]}"
        await base.execute(f'CREATE DATABASE "{test_db}" TEMPLATE postgres')
        await base.close()
        test_dsn = dsn.rsplit("/", 1)[0] + f"/{test_db}"
        # Apply migrations
        pool = await asyncpg.create_pool(test_dsn, min_size=1, max_size=5)
        # Run migrations from migrations/*.sql sorted
        import pathlib

        mig_dir = pathlib.Path(__file__).parents[3] / "migrations"
        for sql_file in sorted(mig_dir.glob("*.sql")):
            sql = sql_file.read_text()
            async with pool.acquire() as conn:
                await conn.execute(sql)
        yield pool
        await pool.close()
        # Drop DB
        base = await asyncpg.connect(dsn)
        await base.execute(f'DROP DATABASE "{test_db}" WITH (FORCE)')
        await base.close()
    except Exception as e:
        pytest.skip(f"DB setup failed: {e}")


@pytest_asyncio.fixture
async def db(db_pool):
    async with db_pool.acquire() as conn:
        # Start transaction
        tr = conn.transaction()
        await tr.start()
        # Set tenant
        try:
            yield conn
        finally:
            await tr.rollback()


@pytest_asyncio.fixture
async def client(db_pool):
    # Use the real app with test DB pool
    # Patch DatabasePool to use test pool
    old_pool = DatabasePool._pool
    DatabasePool._pool = db_pool
    # Ensure settings enable docs for test? Keep disabled to test docs 404
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
async def owner(db):
    email = f"owner-{uuid.uuid4().hex[:6]}@example.com"
    password = "correct-horse-battery-staple"
    hashed = hash_password(password)
    # Insert user directly
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
async def second_user(db, owner):
    email = f"second-{uuid.uuid4().hex[:6]}@example.com"
    password = "second-password-123"
    hashed = hash_password(password)
    row = await db.fetchrow(
        "INSERT INTO users (tenant_id, email, password_hash, role, is_active, created_at, updated_at) VALUES ($1, $2, $3, 'viewer'::user_role, true, NOW(), NOW()) RETURNING id",
        owner.tenant_id,
        email,
        hashed,
    )
    user_id = row["id"]
    return Owner(email, password, user_id, owner.tenant_id)
