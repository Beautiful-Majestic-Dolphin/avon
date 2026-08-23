"""Policy v2 authoring tests — fixtures round-trip via JSON Schema contract."""

import json
import pathlib
import uuid

import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio

FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures" / "policies"


def _fixture(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text())


@pytest.mark.asyncio
async def test_posting_each_valid_fixture_succeeds_and_round_trips(
    client: AsyncClient, admin_user, db
):
    headers = await admin_user.auth_headers(client)
    for fname in ["allow_ssh.json", "deny_all_cameras.json", "time_window.json"]:
        spec = _fixture(fname)
        name = f"test-{uuid.uuid4().hex[:6]}-{fname}"
        r = await client.post(
            "/api/v1/policies/",
            headers=headers,
            json={"name": name, "spec": spec},
        )
        assert r.status_code == 201, f"{fname}: {r.text}"
        body = r.json()
        assert body["name"] == name
        assert body["spec"] == spec
        # round-trip via GET
        pid = body["id"]
        g = await client.get(f"/api/v1/policies/{pid}", headers=headers)
        assert g.status_code == 200
        assert g.json()["spec"] == spec
        # list contains it
        lst = await client.get("/api/v1/policies/", headers=headers)
        assert any(item["id"] == pid for item in lst.json()["items"])


@pytest.mark.asyncio
async def test_posting_invalid_ports_returns_422_with_schema_path(
    client: AsyncClient, admin_user
):
    headers = await admin_user.auth_headers(client)
    spec = _fixture("invalid_ports.json")
    r = await client.post(
        "/api/v1/policies/",
        headers=headers,
        json={"name": f"bad-{uuid.uuid4().hex[:6]}", "spec": spec},
    )
    assert r.status_code == 422, r.text
    detail = r.json().get("detail", {})
    # detail is either string or dict with path
    text = json.dumps(detail) if isinstance(detail, dict) else str(detail)
    assert "ports" in text.lower() or "70000" in text or "pattern" in text.lower()


@pytest.mark.asyncio
async def test_explain_returns_allow_deny_via_fake_control(
    client: AsyncClient, admin_user, fake_control
):
    # fake_control is auto-patched ControlClient via conftest
    # patch explain to return deterministic allow
    async def _fake_explain(tenant_id, device_id, destination, protocol, port):
        return {
            "allow": True,
            "reason": "matched allow_ssh",
            "matched_policies": ["allow_ssh"],
            "cedar": "permit(principal, action, resource);",
        }

    # monkeypatch via fake_control internal patched class — easiest: patch ControlClient directly
    import admin_api.services.control_client as cc

    class _Tmp:
        async def explain(self, tenant_id, device_id, destination, protocol, port):
            return await _fake_explain(
                tenant_id, device_id, destination, protocol, port
            )

        async def revoke_device(self, *a, **kw):
            return None

        async def approve_device(self, *a, **kw):
            return None

        async def list_sessions(self, *a, **kw):
            return []

        async def import_mud(self, *a, **kw):
            return {"created": [], "skipped": []}

    old = cc.ControlClient
    cc.ControlClient = _Tmp  # type: ignore
    try:
        headers = await admin_user.auth_headers(client)
        r = await client.post(
            "/api/v1/policies/explain",
            headers=headers,
            json={
                "device_id": str(uuid.uuid4()),
                "destination": "10.20.0.1",
                "protocol": "tcp",
                "port": 443,
            },
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert "allow" in body
        assert body["allow"] is True
        assert "cedar" in body
    finally:
        cc.ControlClient = old


@pytest.mark.asyncio
async def test_cedar_debug_requires_admin(client: AsyncClient, viewer, admin_user, db):
    # create a policy first
    headers = await admin_user.auth_headers(client)
    spec = _fixture("allow_ssh.json")
    name = f"cedar-{uuid.uuid4().hex[:6]}"
    r = await client.post(
        "/api/v1/policies/", headers=headers, json={"name": name, "spec": spec}
    )
    assert r.status_code == 201
    pid = r.json()["id"]
    # viewer should be forbidden (admin only)
    v_headers = await viewer.auth_headers(client)
    rv = await client.get(f"/api/v1/policies/{pid}/cedar", headers=v_headers)
    assert rv.status_code in (401, 403)
    # admin can fetch cedar
    ra = await client.get(f"/api/v1/policies/{pid}/cedar", headers=headers)
    assert ra.status_code == 200
    assert "cedar" in ra.json()
