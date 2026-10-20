from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from .. import __version__
from ..database import get_db
from ..ratelimit import RedisBackend
from ..rbac import ROLE_PERMISSIONS
from ..schemas import HealthOut, PermissionsOut

router = APIRouter(tags=["meta"])


@router.get("/health", response_model=HealthOut)
def health(request: Request, db: Session = Depends(get_db)) -> HealthOut:
    try:
        db.execute(text("SELECT 1"))
        database = "ok"
    except Exception:  # pragma: no cover - exercised only when the DB is down
        database = "error"
    backend = request.app.state.rate_limiter.backend
    return HealthOut(
        status="ok" if database == "ok" else "degraded",
        version=__version__,
        database=database,
        rate_limiter="redis" if isinstance(backend, RedisBackend) else "memory",
    )


@router.get("/v1/permissions", response_model=PermissionsOut)
def permissions() -> PermissionsOut:
    """Publish the role -> permission map so clients can build their UI from it."""
    return PermissionsOut(
        roles={role.value: sorted(perms) for role, perms in ROLE_PERMISSIONS.items()}
    )
