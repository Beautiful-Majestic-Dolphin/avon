import pytest
from httpx import AsyncClient

pytestmark = pytest.mark.asyncio


async def test_a_scim_token_cannot_deactivate_a_local_owner(
    client: AsyncClient, owner, scim_token
):
    headers = {"Authorization": f"Bearer {scim_token.plaintext}"}
    r = await client.patch(
        f"/scim/v2/Users/{owner.id}",
        headers=headers,
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
    )
    # Should be 403 mutability
    assert r.status_code == 403, f"got {r.status_code} {r.text}"
    assert r.json().get("scimType") == "mutability" or "mutability" in r.text.lower()
    assert await owner.is_active() is True


async def test_an_expired_or_out_of_scope_token_is_refused(
    client: AsyncClient, scim_token, expired_scim_token, read_only_scim_token
):
    assert (
        await client.get(
            "/scim/v2/Users",
            headers={"Authorization": f"Bearer {expired_scim_token.plaintext}"},
        )
    ).status_code == 401
    r = await client.post(
        "/scim/v2/Users",
        headers={"Authorization": f"Bearer {read_only_scim_token.plaintext}"},
        json={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "x@example.com",
        },
    )
    assert (
        r.status_code == 403
    ), f"read-only token should not create, got {r.status_code} {r.text}"


async def test_scim_is_scoped_to_its_tenant(
    client: AsyncClient, scim_token, other_tenant
):
    headers = {"Authorization": f"Bearer {scim_token.plaintext}"}
    r = await client.get(f"/scim/v2/Users/{other_tenant.user_id}", headers=headers)
    assert (
        r.status_code == 404
    ), f"scim should be tenant-scoped, got {r.status_code} {r.text}"
