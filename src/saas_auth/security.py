"""Password hashing, JWT access tokens and the request principal (user or API key)."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session

from .config import Settings
from .database import get_db
from .models import ApiKey, User
from .utils import constant_time_equals, generate_token, hash_token, new_id, utcnow

log = logging.getLogger(__name__)

API_KEY_PREFIX = "sk"
_bearer = HTTPBearer(auto_error=False)
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# --------------------------------------------------------------------------- passwords


def hash_password(password: str, rounds: int = 12) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=rounds)).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except ValueError:
        return False


# --------------------------------------------------------------------------- JWT


def create_access_token(
    user_id: str, settings: Settings, expires_delta: timedelta | None = None
) -> str:
    now = utcnow()
    ttl = expires_delta or timedelta(seconds=settings.access_token_ttl_seconds)
    payload: dict[str, Any] = {
        "sub": user_id,
        "type": "access",
        "jti": new_id(),
        "iat": int(now.timestamp()),
        "exp": int((now + ttl).timestamp()),
        "iss": settings.app_name,
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str, settings: Settings) -> dict[str, Any]:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            issuer=settings.app_name,
            options={"require": ["exp", "sub", "iat"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Token expired") from exc
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from exc
    if payload.get("type") != "access":
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token type")
    return payload


# --------------------------------------------------------------------------- API keys


def generate_api_key() -> tuple[str, str, str]:
    """Return (raw_key, prefix, secret_hash). Only `raw_key` is ever shown to the caller."""
    # The prefix is hex so it can never contain "_", the separator parse_api_key splits on.
    # (token_urlsafe output may contain "_", which made roughly 1 in 8 keys unparseable.)
    prefix = secrets.token_hex(4)
    secret = generate_token(32)
    raw = f"{API_KEY_PREFIX}_{prefix}_{secret}"
    return raw, prefix, hash_token(secret)


def parse_api_key(raw: str) -> tuple[str, str] | None:
    parts = raw.strip().split("_", 2)
    if len(parts) != 3 or parts[0] != API_KEY_PREFIX or not parts[1] or not parts[2]:
        return None
    return parts[1], parts[2]


def authenticate_api_key(db: Session, raw: str) -> ApiKey | None:
    parsed = parse_api_key(raw)
    if parsed is None:
        return None
    prefix, secret = parsed
    key = db.scalar(select(ApiKey).where(ApiKey.prefix == prefix))
    if key is None or key.revoked_at is not None:
        return None
    if not constant_time_equals(key.hashed_secret, hash_token(secret)):
        return None
    return key


# --------------------------------------------------------------------------- principal


@dataclass
class Principal:
    """Who is calling: an authenticated user (JWT) or an organization API key."""

    user: User | None = None
    api_key: ApiKey | None = None

    @property
    def kind(self) -> str:
        return "user" if self.user is not None else "api_key"


def get_principal(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Security(_bearer),
    api_key: str | None = Security(_api_key_header),
    db: Session = Depends(get_db),
) -> Principal:
    settings: Settings = request.app.state.settings

    if credentials is not None and credentials.scheme.lower() == "bearer":
        payload = decode_access_token(credentials.credentials, settings)
        user = db.get(User, payload["sub"])
        if user is None or not user.is_active:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "User not found or inactive")
        return Principal(user=user)

    if api_key:
        key = authenticate_api_key(db, api_key)
        if key is None:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid API key")
        return Principal(api_key=key)

    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Not authenticated",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(principal: Principal = Depends(get_principal)) -> User:
    """Endpoints that only make sense for a human user (profile, org creation, invitations)."""
    if principal.user is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "This endpoint requires a user session")
    return principal.user
