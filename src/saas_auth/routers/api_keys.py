from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import ApiKey
from ..rbac import TenantContext, require
from ..schemas import ApiKeyCreate, ApiKeyCreated, ApiKeyOut, MessageOut
from ..security import generate_api_key
from ..utils import utcnow

router = APIRouter(prefix="/v1/orgs/{org_id}/api-keys", tags=["api-keys"])


@router.post("", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def create_api_key(
    payload: ApiKeyCreate,
    ctx: TenantContext = Depends(require("api_keys:create")),
    db: Session = Depends(get_db),
) -> ApiKeyCreated:
    if ctx.user is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "API keys cannot mint other API keys")
    # A key can never carry more than the creator holds.
    too_broad = sorted(set(payload.scopes) - ctx.permissions)
    if too_broad:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail={"message": "Scopes exceed your permissions", "scopes": too_broad},
        )
    raw, prefix, hashed = generate_api_key()
    key = ApiKey(
        org_id=ctx.org.id,
        name=payload.name.strip(),
        prefix=prefix,
        hashed_secret=hashed,
        scopes=payload.scopes,
        created_by=ctx.user.id,
    )
    db.add(key)
    db.commit()
    return ApiKeyCreated(
        id=key.id,
        org_id=key.org_id,
        name=key.name,
        prefix=key.prefix,
        scopes=key.scopes,
        last_used_at=key.last_used_at,
        revoked_at=key.revoked_at,
        created_at=key.created_at,
        key=raw,
    )


@router.get("", response_model=list[ApiKeyOut])
def list_api_keys(
    ctx: TenantContext = Depends(require("api_keys:read")), db: Session = Depends(get_db)
) -> list[ApiKey]:
    return list(
        db.scalars(
            select(ApiKey).where(ApiKey.org_id == ctx.org.id).order_by(ApiKey.created_at.desc())
        )
    )


@router.delete("/{key_id}", response_model=MessageOut)
def revoke_api_key(
    key_id: str,
    ctx: TenantContext = Depends(require("api_keys:revoke")),
    db: Session = Depends(get_db),
) -> MessageOut:
    key = db.scalar(select(ApiKey).where(ApiKey.id == key_id, ApiKey.org_id == ctx.org.id))
    if key is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API key not found")
    if key.revoked_at is None:
        key.revoked_at = utcnow()
        db.commit()
    return MessageOut(message="API key revoked")
