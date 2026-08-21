"""SCIM 2.0 business logic for AVON Admin API.

Maps SCIM operations to Avon database queries. Handles user provisioning,
group management, and deprovisioning with device suspension.
"""

import secrets
from uuid import UUID

import asyncpg
import structlog
from passlib.context import CryptContext

from admin_api.db.models import DbPod, DbUser
from admin_api.db.queries import (
    ActivityQueries,
    PodQueries,
    UserPodQueries,
    UserQueries,
)
from admin_api.scim.schemas import (
    ScimGroupRef,
    ScimGroupResponse,
    ScimMemberRef,
    ScimMeta,
    ScimName,
    ScimUserResponse,
)

logger = structlog.get_logger()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _user_to_scim(
    user: DbUser, groups: list[ScimGroupRef] | None = None
) -> ScimUserResponse:
    """Convert a DbUser to a SCIM User response."""
    groups = groups if groups is not None else []
    name = None
    if user.full_name:
        name = ScimName(formatted=user.full_name)

    return ScimUserResponse(
        id=str(user.id),
        userName=user.email,
        name=name,
        displayName=user.full_name,
        active=user.is_active,
        externalId=user.external_id,
        groups=groups,
        meta=ScimMeta(
            resourceType="User",
            created=user.created_at.isoformat() if user.created_at else None,
            lastModified=user.updated_at.isoformat() if user.updated_at else None,
        ),
    )


def _pod_to_scim(
    pod: DbPod, members: list[ScimMemberRef] | None = None
) -> ScimGroupResponse:
    """Convert a DbPod to a SCIM Group response."""
    members = members if members is not None else []
    return ScimGroupResponse(
        id=str(pod.id),
        displayName=pod.name,
        externalId=pod.external_id,
        members=members,
        meta=ScimMeta(
            resourceType="Group",
            created=pod.created_at.isoformat() if pod.created_at else None,
            lastModified=pod.updated_at.isoformat() if pod.updated_at else None,
        ),
    )


class ScimService:
    """SCIM 2.0 business logic."""

    def __init__(self, db: asyncpg.Connection):
        self.db = db

    # --- User Operations ---

    async def create_user(
        self,
        user_name: str,
        full_name: str | None,
        active: bool,
        external_id: str | None,
    ) -> ScimUserResponse:
        """Create a SCIM-managed user."""
        # Check for existing user by externalId or email
        if external_id:
            existing = await UserQueries.get_user_by_external_id(self.db, external_id)
            if existing:
                return _user_to_scim(existing)

        existing = await UserQueries.get_user_by_email(self.db, user_name)
        if existing:
            raise ValueError(f"User with email {user_name} already exists")

        # Generate a random password (SCIM users authenticate via IdP, not password)
        random_password = secrets.token_urlsafe(32)
        hashed_password = pwd_context.hash(random_password)

        user = await UserQueries.create_user(
            self.db,
            email=user_name,
            hashed_password=hashed_password,
            full_name=full_name,
        )

        # Set SCIM-specific fields
        await UserQueries.update_user(
            self.db,
            user.id,
            external_id=external_id,
            managed_by="scim",
            is_active=active,
        )

        user = await UserQueries.get_user(self.db, user.id)

        await ActivityQueries.log_activity(
            self.db,
            event_type="scim.user.created",
            actor_type="scim",
            target_id=user.id,
            target_type="user",
            details={"email": user_name, "external_id": external_id},
        )

        logger.info("scim_user_created", email=user_name, user_id=str(user.id))
        return _user_to_scim(user)

    async def get_user(self, user_id: UUID) -> ScimUserResponse | None:
        """Get a user by ID as a SCIM response."""
        user = await UserQueries.get_user(self.db, user_id)
        if user is None:
            return None

        pods = await UserPodQueries.get_user_pods(self.db, user_id)
        groups = []
        for pod_id in pods:
            pod = await PodQueries.get_pod(self.db, pod_id)
            if pod:
                groups.append(ScimGroupRef(value=str(pod.id), display=pod.name))

        return _user_to_scim(user, groups)

    async def update_user(
        self,
        user_id: UUID,
        user_name: str | None = None,
        full_name: str | None = None,
        active: bool | None = None,
        external_id: str | None = None,
    ) -> ScimUserResponse | None:
        """Update a user. Handles deprovisioning if active=False."""
        user = await UserQueries.get_user(self.db, user_id)
        if user is None:
            return None

        # Detect deprovisioning
        if active is False and user.is_active:
            await self._deprovision_user(user_id)
        elif active is not None:
            await UserQueries.update_user(self.db, user_id, is_active=active)

        # Update other fields
        await UserQueries.update_user(
            self.db,
            user_id,
            email=user_name,
            full_name=full_name,
            external_id=external_id,
        )

        updated = await UserQueries.get_user(self.db, user_id)
        return _user_to_scim(updated) if updated else None

    async def delete_user(self, user_id: UUID) -> bool:
        """Deactivate a user and suspend their devices (soft delete)."""
        user = await UserQueries.get_user(self.db, user_id)
        if user is None:
            return False

        await self._deprovision_user(user_id)

        await ActivityQueries.log_activity(
            self.db,
            event_type="scim.user.deleted",
            actor_type="scim",
            target_id=user_id,
            target_type="user",
        )

        logger.info("scim_user_deleted", user_id=str(user_id))
        return True

    async def list_users(
        self,
        offset: int = 0,
        limit: int = 100,
        filter_column: str | None = None,
        filter_op: str | None = None,
        filter_value: str | None = None,
    ) -> tuple[list[ScimUserResponse], int]:
        """List users with optional SCIM filter."""
        if filter_column and filter_op and filter_value:
            users, total = await UserQueries.search_users(
                self.db, filter_column, filter_op, filter_value, offset, limit
            )
        else:
            users = await UserQueries.list_users(self.db, skip=offset, limit=limit)
            total = await UserQueries.count_users(self.db)

        results = [_user_to_scim(u) for u in users]
        return results, total

    async def _deprovision_user(self, user_id: UUID) -> None:
        """Deactivate a user and suspend all their enrolled devices."""
        await UserQueries.update_user(self.db, user_id, is_active=False)

        # Suspend all devices enrolled by this user
        devices = await self.db.fetch(
            "SELECT id FROM devices WHERE enrolled_by = $1 AND status = 'active'",
            user_id,
        )
        for device in devices:
            await self.db.execute(
                "UPDATE devices SET status = 'suspended', updated_at = NOW() WHERE id = $1",
                device["id"],
            )
            await ActivityQueries.log_activity(
                self.db,
                event_type="scim.device.suspended",
                actor_type="scim",
                target_id=device["id"],
                target_type="device",
                details={"reason": "user_deprovisioned", "user_id": str(user_id)},
            )

        logger.info(
            "scim_user_deprovisioned",
            user_id=str(user_id),
            devices_suspended=len(devices),
        )

    # --- Group Operations ---

    async def create_group(
        self,
        display_name: str,
        external_id: str | None,
        member_ids: list[UUID],
    ) -> ScimGroupResponse:
        """Create a SCIM-managed group (Avon pod)."""
        if external_id:
            existing = await PodQueries.get_pod_by_external_id(self.db, external_id)
            if existing:
                return await self._pod_to_scim_with_members(existing)

        pod = await PodQueries.create_pod(self.db, name=display_name)

        # Set SCIM fields
        await self.db.execute(
            "UPDATE pods SET external_id = $1, managed_by = 'scim' WHERE id = $2",
            external_id,
            pod.id,
        )

        # Add members
        for uid in member_ids:
            await UserPodQueries.add_user_to_pod(self.db, uid, pod.id)

        pod = await PodQueries.get_pod(self.db, pod.id)

        await ActivityQueries.log_activity(
            self.db,
            event_type="scim.group.created",
            actor_type="scim",
            target_id=pod.id,
            target_type="pod",
            details={"name": display_name, "external_id": external_id},
        )

        logger.info("scim_group_created", name=display_name, pod_id=str(pod.id))
        return await self._pod_to_scim_with_members(pod)

    async def get_group(self, pod_id: UUID) -> ScimGroupResponse | None:
        """Get a group by ID as a SCIM response."""
        pod = await PodQueries.get_pod(self.db, pod_id)
        if pod is None:
            return None
        return await self._pod_to_scim_with_members(pod)

    async def update_group(
        self,
        pod_id: UUID,
        display_name: str | None = None,
        external_id: str | None = None,
        member_ids: list[UUID] | None = None,
    ) -> ScimGroupResponse | None:
        """Update a group. If member_ids is provided, replaces all members."""
        pod = await PodQueries.get_pod(self.db, pod_id)
        if pod is None:
            return None

        if display_name:
            await PodQueries.update_pod(self.db, pod_id, name=display_name)
        if external_id is not None:
            await self.db.execute(
                "UPDATE pods SET external_id = $1, updated_at = NOW() WHERE id = $2",
                external_id,
                pod_id,
            )
        if member_ids is not None:
            await UserPodQueries.set_pod_members(self.db, pod_id, member_ids)

        pod = await PodQueries.get_pod(self.db, pod_id)
        return await self._pod_to_scim_with_members(pod)

    async def add_group_members(self, pod_id: UUID, user_ids: list[UUID]) -> None:
        """Add members to a group."""
        for uid in user_ids:
            await UserPodQueries.add_user_to_pod(self.db, uid, pod_id)

    async def remove_group_members(self, pod_id: UUID, user_ids: list[UUID]) -> None:
        """Remove members from a group."""
        for uid in user_ids:
            await UserPodQueries.remove_user_from_pod(self.db, uid, pod_id)

    async def delete_group(self, pod_id: UUID) -> bool:
        """Delete a group (pod)."""
        pod = await PodQueries.get_pod(self.db, pod_id)
        if pod is None:
            return False

        await PodQueries.delete_pod(self.db, pod_id)

        await ActivityQueries.log_activity(
            self.db,
            event_type="scim.group.deleted",
            actor_type="scim",
            target_id=pod_id,
            target_type="pod",
        )

        logger.info("scim_group_deleted", pod_id=str(pod_id))
        return True

    async def list_groups(
        self,
        offset: int = 0,
        limit: int = 100,
        filter_column: str | None = None,
        filter_op: str | None = None,
        filter_value: str | None = None,
    ) -> tuple[list[ScimGroupResponse], int]:
        """List groups with optional SCIM filter."""
        if filter_column and filter_op and filter_value:
            pods, total = await PodQueries.search_pods(
                self.db, filter_column, filter_op, filter_value, offset, limit
            )
        else:
            pods = await PodQueries.list_pods(self.db, skip=offset, limit=limit)
            total = await PodQueries.count_pods(self.db)

        results = []
        for pod in pods:
            scim_group = await self._pod_to_scim_with_members(pod)
            results.append(scim_group)
        return results, total

    async def _pod_to_scim_with_members(self, pod: DbPod) -> ScimGroupResponse:
        """Convert a pod to SCIM Group response with member list."""
        users = await UserPodQueries.get_pod_users(self.db, pod.id)
        members = [ScimMemberRef(value=str(u.id), display=u.email) for u in users]
        return _pod_to_scim(pod, members)
