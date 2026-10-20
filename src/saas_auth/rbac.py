"""Roles, the permission map and the `require(...)` route dependency.

Roles are per organization (a user can be owner of one org and viewer of another).
Permissions are flat strings `resource:action` so the same vocabulary doubles as API key scopes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from fastapi import Depends, HTTPException, Path, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from .database import get_db
from .models import ApiKey, Membership, Organization, User
from .security import Principal, get_principal
from .utils import utcnow


class Role(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    MEMBER = "member"
    VIEWER = "viewer"


ROLE_RANK: dict[str, int] = {
    Role.VIEWER: 0,
    Role.MEMBER: 1,
    Role.ADMIN: 2,
    Role.OWNER: 3,
}

_VIEWER = {
    "org:read",
    "members:read",
    "projects:read",
}
_MEMBER = _VIEWER | {
    "projects:create",
    "projects:update",
}
_ADMIN = _MEMBER | {
    "org:update",
    "members:invite",
    "members:update",
    "members:remove",
    "projects:delete",
    "api_keys:read",
    "api_keys:create",
    "api_keys:revoke",
}
_OWNER = _ADMIN | {
    "org:delete",
    "billing:manage",
}

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    Role.VIEWER: frozenset(_VIEWER),
    Role.MEMBER: frozenset(_MEMBER),
    Role.ADMIN: frozenset(_ADMIN),
    Role.OWNER: frozenset(_OWNER),
}

ALL_PERMISSIONS: frozenset[str] = ROLE_PERMISSIONS[Role.OWNER]


def permissions_for(role: str) -> frozenset[str]:
    try:
        return ROLE_PERMISSIONS[Role(role)]
    except ValueError as exc:
        raise ValueError(f"unknown role {role!r}") from exc


def has_permission(role: str, permission: str) -> bool:
    return permission in permissions_for(role)


@dataclass
class TenantContext:
    """Resolved per request: who is acting, inside which organization, with what permissions."""

    org: Organization
    principal: Principal
    permissions: frozenset[str]
    role: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def user(self) -> User | None:
        return self.principal.user

    @property
    def api_key(self) -> ApiKey | None:
        return self.principal.api_key

    @property
    def actor_id(self) -> str | None:
        if self.principal.user is not None:
            return self.principal.user.id
        return None

    def can(self, permission: str) -> bool:
        return permission in self.permissions


def get_membership(db: Session, user_id: str, org_id: str) -> Membership | None:
    return db.scalar(
        select(Membership).where(Membership.user_id == user_id, Membership.org_id == org_id)
    )


def resolve_tenant(
    request: Request,
    org_id: str = Path(..., description="Organization id"),
    principal: Principal = Depends(get_principal),
    db: Session = Depends(get_db),
) -> TenantContext:
    """Load the organization from the path and work out the caller's permissions inside it.

    Non-members get a 404 rather than 403 so organization ids cannot be enumerated.
    """
    org = db.get(Organization, org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")

    if principal.api_key is not None:
        key = principal.api_key
        if key.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
        key.last_used_at = utcnow()
        db.commit()
        return TenantContext(org=org, principal=principal, permissions=frozenset(key.scopes))

    assert principal.user is not None
    membership = get_membership(db, principal.user.id, org.id)
    if membership is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Organization not found")
    return TenantContext(
        org=org,
        principal=principal,
        permissions=permissions_for(membership.role),
        role=membership.role,
    )


def require(*permissions: str):
    """Build a dependency that resolves the tenant context and enforces the given permissions.

    Usage::

        @router.post("/v1/orgs/{org_id}/projects")
        def create_project(ctx: TenantContext = Depends(require("projects:create"))): ...
    """
    unknown = set(permissions) - ALL_PERMISSIONS
    if unknown:
        raise ValueError(f"unknown permissions: {sorted(unknown)}")

    def dependency(ctx: TenantContext = Depends(resolve_tenant)) -> TenantContext:
        missing = [p for p in permissions if p not in ctx.permissions]
        if missing:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                detail={"message": "Insufficient permissions", "missing": missing},
            )
        return ctx

    return dependency
