"""Rotating refresh tokens with reuse detection, plus single-use email tokens.

Design:
* Only a SHA-256 hash of each refresh token is stored.
* Each login starts a new *family*. Refreshing marks the presented token as revoked and issues a
  child in the same family.
* Presenting a token that was already rotated (``revoked_at`` set) is treated as theft: the whole
  family is revoked, forcing every device on that chain to log in again.
"""

from __future__ import annotations

import logging

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from .config import Settings
from .models import EmailToken, RefreshToken, User
from .utils import generate_token, hash_token, in_seconds, is_expired, new_id, utcnow

log = logging.getLogger(__name__)


class RefreshTokenError(Exception):
    """Base class for refresh token failures."""


class InvalidRefreshToken(RefreshTokenError):
    pass


class RefreshTokenReused(RefreshTokenError):
    """A previously rotated token was presented again; the family has been revoked."""


def issue_refresh_token(
    db: Session,
    user: User,
    settings: Settings,
    family_id: str | None = None,
    user_agent: str | None = None,
) -> tuple[str, RefreshToken]:
    raw = generate_token(48)
    record = RefreshToken(
        user_id=user.id,
        token_hash=hash_token(raw),
        family_id=family_id or new_id(),
        expires_at=in_seconds(settings.refresh_token_ttl_seconds),
        user_agent=(user_agent or "")[:255] or None,
    )
    db.add(record)
    db.flush()
    return raw, record


def revoke_family(db: Session, family_id: str) -> int:
    result = db.execute(
        update(RefreshToken)
        .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    return result.rowcount or 0


def revoke_all_for_user(db: Session, user_id: str) -> int:
    result = db.execute(
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.revoked_at.is_(None))
        .values(revoked_at=utcnow())
    )
    return result.rowcount or 0


def revoke_refresh_token(db: Session, raw: str) -> bool:
    record = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw)))
    if record is None or record.revoked_at is not None:
        return False
    record.revoked_at = utcnow()
    return True


def rotate_refresh_token(
    db: Session, raw: str, settings: Settings, user_agent: str | None = None
) -> tuple[str, RefreshToken, User]:
    record = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(raw)))
    if record is None:
        raise InvalidRefreshToken("unknown refresh token")

    if record.revoked_at is not None:
        revoked = revoke_family(db, record.family_id)
        db.commit()
        log.warning(
            "refresh token reuse detected user=%s family=%s revoked=%d",
            record.user_id,
            record.family_id,
            revoked,
        )
        raise RefreshTokenReused("refresh token reuse detected; session family revoked")

    if is_expired(record.expires_at):
        record.revoked_at = utcnow()
        db.commit()
        raise InvalidRefreshToken("refresh token expired")

    user = db.get(User, record.user_id)
    if user is None or not user.is_active:
        raise InvalidRefreshToken("user inactive")

    new_raw, new_record = issue_refresh_token(
        db, user, settings, family_id=record.family_id, user_agent=user_agent
    )
    record.revoked_at = utcnow()
    record.replaced_by_id = new_record.id
    return new_raw, new_record, user


# --------------------------------------------------------------------------- email tokens

PURPOSE_VERIFY = "verify"
PURPOSE_RESET = "reset"


def issue_email_token(db: Session, user: User, purpose: str, settings: Settings) -> str:
    # Invalidate any outstanding token for the same purpose so only the latest email works.
    db.execute(
        update(EmailToken)
        .where(
            EmailToken.user_id == user.id,
            EmailToken.purpose == purpose,
            EmailToken.used_at.is_(None),
        )
        .values(used_at=utcnow())
    )
    raw = generate_token(32)
    db.add(
        EmailToken(
            user_id=user.id,
            purpose=purpose,
            token_hash=hash_token(raw),
            expires_at=in_seconds(settings.email_token_ttl_seconds),
        )
    )
    db.flush()
    return raw


def consume_email_token(db: Session, raw: str, purpose: str) -> User | None:
    record = db.scalar(
        select(EmailToken).where(
            EmailToken.token_hash == hash_token(raw), EmailToken.purpose == purpose
        )
    )
    if record is None or record.used_at is not None or is_expired(record.expires_at):
        return None
    record.used_at = utcnow()
    return db.get(User, record.user_id)
