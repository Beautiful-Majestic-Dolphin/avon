"""RBAC for AVON Admin API."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Literal

from fastapi import Depends, HTTPException, status

from admin_api.auth.dependencies import CurrentUser, get_current_user

Role = Literal["owner", "admin", "viewer"]
_ORDER = {"viewer": 0, "admin": 1, "owner": 2}

VIEWER_HIDDEN = {
    "fingerprint",
    "current_token",
    "previous_token",
    "posture",
    "token",
    "enrollment_token",
    "ppk",
}


def require_role(*roles: Role) -> Callable[..., Awaitable[CurrentUser]]:
    minimum = min(_ORDER[r] for r in roles)

    async def dependency(
        current: CurrentUser = Depends(get_current_user),
    ) -> CurrentUser:
        role = getattr(current.user, "role", "viewer")
        # Map is_admin to owner for legacy
        if getattr(current.user, "is_admin", False):
            role = "owner"
        if _ORDER.get(role, -1) < minimum:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="insufficient role"
            )
        return current

    return dependency


def redact_for(
    user: CurrentUser, payload: dict, secret_fields: set[str] = VIEWER_HIDDEN
) -> dict:
    role = getattr(user.user, "role", "viewer")
    if getattr(user.user, "is_admin", False):
        role = "owner"
    if role != "viewer":
        return payload
    return {k: v for k, v in payload.items() if k not in secret_fields}
