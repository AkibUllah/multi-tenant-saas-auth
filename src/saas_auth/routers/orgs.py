from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Membership, Organization, User
from ..rbac import Role, TenantContext, require
from ..schemas import MessageOut, OrgCreate, OrgOut, OrgUpdate, OrgWithRoleOut
from ..security import get_current_user

router = APIRouter(prefix="/v1/orgs", tags=["organizations"])


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "org"


def unique_slug(db: Session, base: str) -> str:
    slug, n = base, 2
    while db.scalar(select(Organization.id).where(Organization.slug == slug)) is not None:
        slug = f"{base}-{n}"
        n += 1
    return slug


@router.post("", response_model=OrgWithRoleOut, status_code=status.HTTP_201_CREATED)
def create_org(
    payload: OrgCreate, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> OrgWithRoleOut:
    if payload.slug:
        if db.scalar(select(Organization.id).where(Organization.slug == payload.slug)):
            raise HTTPException(status.HTTP_409_CONFLICT, "Slug already taken")
        slug = payload.slug
    else:
        slug = unique_slug(db, slugify(payload.name))
    org = Organization(name=payload.name.strip(), slug=slug)
    db.add(org)
    db.flush()
    db.add(Membership(user_id=user.id, org_id=org.id, role=Role.OWNER.value))
    db.commit()
    return OrgWithRoleOut(
        id=org.id, name=org.name, slug=org.slug, created_at=org.created_at, role=Role.OWNER.value
    )


@router.get("", response_model=list[OrgWithRoleOut])
def list_my_orgs(
    user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> list[OrgWithRoleOut]:
    rows = db.execute(
        select(Organization, Membership.role)
        .join(Membership, Membership.org_id == Organization.id)
        .where(Membership.user_id == user.id)
        .order_by(Organization.created_at)
    ).all()
    return [
        OrgWithRoleOut(id=o.id, name=o.name, slug=o.slug, created_at=o.created_at, role=role)
        for o, role in rows
    ]


@router.get("/{org_id}", response_model=OrgWithRoleOut)
def get_org(ctx: TenantContext = Depends(require("org:read"))) -> OrgWithRoleOut:
    return OrgWithRoleOut(
        id=ctx.org.id,
        name=ctx.org.name,
        slug=ctx.org.slug,
        created_at=ctx.org.created_at,
        role=ctx.role or "api_key",
    )


@router.patch("/{org_id}", response_model=OrgOut)
def update_org(
    payload: OrgUpdate,
    ctx: TenantContext = Depends(require("org:update")),
    db: Session = Depends(get_db),
) -> Organization:
    if payload.name is not None:
        ctx.org.name = payload.name.strip()
    db.commit()
    return ctx.org


@router.delete("/{org_id}", response_model=MessageOut)
def delete_org(
    ctx: TenantContext = Depends(require("org:delete")), db: Session = Depends(get_db)
) -> MessageOut:
    db.delete(ctx.org)
    db.commit()
    return MessageOut(message="Organization deleted")
