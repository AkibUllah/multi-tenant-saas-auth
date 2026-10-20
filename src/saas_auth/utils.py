"""Small shared helpers: UUIDs, clocks, token hashing."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta, timezone


def new_id() -> str:
    return str(uuid.uuid4())


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def ensure_aware(dt: datetime | None) -> datetime | None:
    """SQLite drops tzinfo on round-trip; normalise everything to aware UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def in_seconds(seconds: int) -> datetime:
    return utcnow() + timedelta(seconds=seconds)


def is_expired(expires_at: datetime | None) -> bool:
    aware = ensure_aware(expires_at)
    return aware is not None and aware <= utcnow()


def generate_token(nbytes: int = 32) -> str:
    """URL-safe opaque token with `nbytes` of entropy."""
    return secrets.token_urlsafe(nbytes)


def hash_token(raw: str) -> str:
    """Tokens are high-entropy random strings, so a SHA-256 digest is sufficient for storage."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return secrets.compare_digest(a.encode("utf-8"), b.encode("utf-8"))
