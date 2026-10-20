from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Membership, User
from ..rbac import Role, TenantContext, require
from ..schemas import MemberOut, MessageOut, RoleUpdate

router = APIRouter(prefix="/v1/orgs/{org_id}/members", tags=["members"])


def _owner_count(db: Session, org_id: str) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(Membership)
            .where(Membership.org_id == org_id, Membership.role == Role.OWNER.value)
        )
        or 0
    )


def _target(db: Session, org_id: str, user_id: str) -> Membership:
    membership = db.scalar(
        select(Membership).where(Membership.org_id == org_id, Membership.user_id == user_id)
    )
    if membership is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Member not found")
    return membership


@router.get("", response_model=list[MemberOut])
def list_members(
    ctx: TenantContext = Depends(require("members:read")), db: Session = Depends(get_db)
) -> list[MemberOut]:
    rows = db.execute(
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.org_id == ctx.org.id)
        .order_by(Membership.created_at)
    ).all()
    return [
        MemberOut(
            user_id=u.id, email=u.email, full_name=u.full_name, role=m.role, joined_at=m.created_at
        )
        for m, u in rows
    ]


@router.patch("/{user_id}", response_model=MemberOut)
def update_member_role(
    user_id: str,
    payload: RoleUpdate,
    ctx: TenantContext = Depends(require("members:update")),
    db: Session = Depends(get_db),
) -> MemberOut:
    membership = _target(db, ctx.org.id, user_id)
    new_role = payload.role.value

    touches_owner = membership.role == Role.OWNER.value or new_role == Role.OWNER.value
    if touches_owner and ctx.role != Role.OWNER.value:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only owners can grant or revoke ownership")
    if (
        membership.role == Role.OWNER.value
        and new_role != Role.OWNER.value
        and _owner_count(db, ctx.org.id) <= 1
    ):
        raise HTTPException(
            status.HTTP_409_CONFLICT, "An organization must keep at least one owner"
        )

    membership.role = new_role
    db.commit()
    user = db.get(User, user_id)
    assert user is not None
    return MemberOut(
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=membership.role,
        joined_at=membership.created_at,
    )


@router.delete("/{user_id}", response_model=MessageOut)
def remove_member(
    user_id: str,
    ctx: TenantContext = Depends(require("members:remove")),
    db: Session = Depends(get_db),
) -> MessageOut:
    membership = _target(db, ctx.org.id, user_id)
    if membership.role == Role.OWNER.value:
        if ctx.role != Role.OWNER.value:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Only owners can remove an owner")
        if _owner_count(db, ctx.org.id) <= 1:
            raise HTTPException(
                status.HTTP_409_CONFLICT, "An organization must keep at least one owner"
            )
    db.delete(membership)
    db.commit()
    return MessageOut(message="Member removed")


@router.post("/leave", response_model=MessageOut)
def leave_org(
    ctx: TenantContext = Depends(require("org:read")), db: Session = Depends(get_db)
) -> MessageOut:
    if ctx.user is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API keys cannot leave an organization")
    membership = _target(db, ctx.org.id, ctx.user.id)
    if membership.role == Role.OWNER.value and _owner_count(db, ctx.org.id) <= 1:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Transfer ownership before leaving the organization"
        )
    db.delete(membership)
    db.commit()
    return MessageOut(message="You left the organization")
