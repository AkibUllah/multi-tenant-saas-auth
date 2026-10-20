from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..emailer import Mailer
from ..models import Invitation, Membership, Organization, User
from ..rbac import Role, TenantContext, get_membership, require
from ..schemas import (
    AcceptInvitationOut,
    InvitationCreate,
    InvitationOut,
    MessageOut,
    OrgOut,
    TokenIn,
)
from ..security import get_current_user
from ..utils import generate_token, hash_token, in_seconds, is_expired, utcnow

router = APIRouter(tags=["invitations"])


@router.post(
    "/v1/orgs/{org_id}/invitations",
    response_model=InvitationOut,
    status_code=status.HTTP_201_CREATED,
)
def create_invitation(
    payload: InvitationCreate,
    request: Request,
    ctx: TenantContext = Depends(require("members:invite")),
    db: Session = Depends(get_db),
) -> Invitation:
    settings = request.app.state.settings
    email = payload.email.lower()

    if payload.role == Role.OWNER and ctx.role != Role.OWNER.value:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Only owners can invite new owners")

    existing_user = db.scalar(select(User).where(User.email == email))
    if existing_user and get_membership(db, existing_user.id, ctx.org.id):
        raise HTTPException(status.HTTP_409_CONFLICT, "User is already a member")

    pending = db.scalar(
        select(Invitation).where(
            Invitation.org_id == ctx.org.id,
            Invitation.email == email,
            Invitation.accepted_at.is_(None),
            Invitation.revoked_at.is_(None),
        )
    )
    if pending is not None and not is_expired(pending.expires_at):
        raise HTTPException(status.HTTP_409_CONFLICT, "An invitation is already pending")

    raw = generate_token(32)
    invitation = Invitation(
        org_id=ctx.org.id,
        email=email,
        role=payload.role.value,
        token_hash=hash_token(raw),
        invited_by=ctx.actor_id,
        expires_at=in_seconds(settings.invitation_ttl_seconds),
    )
    db.add(invitation)
    db.commit()
    Mailer(request.app.state.email, settings).send_invitation(
        email, ctx.org.name, invitation.role, raw
    )
    return invitation


@router.get("/v1/orgs/{org_id}/invitations", response_model=list[InvitationOut])
def list_invitations(
    ctx: TenantContext = Depends(require("members:read")), db: Session = Depends(get_db)
) -> list[Invitation]:
    return list(
        db.scalars(
            select(Invitation)
            .where(Invitation.org_id == ctx.org.id)
            .order_by(Invitation.created_at.desc())
        )
    )


@router.delete("/v1/orgs/{org_id}/invitations/{invitation_id}", response_model=MessageOut)
def revoke_invitation(
    invitation_id: str,
    ctx: TenantContext = Depends(require("members:invite")),
    db: Session = Depends(get_db),
) -> MessageOut:
    invitation = db.scalar(
        select(Invitation).where(Invitation.id == invitation_id, Invitation.org_id == ctx.org.id)
    )
    if invitation is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Invitation not found")
    if invitation.accepted_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Invitation already accepted")
    invitation.revoked_at = utcnow()
    db.commit()
    return MessageOut(message="Invitation revoked")


@router.post("/v1/invitations/accept", response_model=AcceptInvitationOut)
def accept_invitation(
    payload: TokenIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)
) -> AcceptInvitationOut:
    invitation = db.scalar(
        select(Invitation).where(Invitation.token_hash == hash_token(payload.token))
    )
    if (
        invitation is None
        or invitation.accepted_at is not None
        or invitation.revoked_at is not None
        or is_expired(invitation.expires_at)
    ):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid or expired invitation")
    if invitation.email != user.email.lower():
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "This invitation was issued to a different email address"
        )
    if get_membership(db, user.id, invitation.org_id) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "You are already a member")

    db.add(Membership(user_id=user.id, org_id=invitation.org_id, role=invitation.role))
    invitation.accepted_at = utcnow()
    db.commit()
    org = db.get(Organization, invitation.org_id)
    assert org is not None
    return AcceptInvitationOut(org=OrgOut.model_validate(org), role=invitation.role)
