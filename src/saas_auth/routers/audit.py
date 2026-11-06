from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from .. import audit
from ..audit import Action, EventFilter
from ..database import get_db
from ..rbac import TenantContext, require
from ..schemas import AuditEventOut, AuditEventPage
from ..utils import ensure_aware

router = APIRouter(prefix="/v1/orgs/{org_id}/audit-events", tags=["audit"])

ID_PATTERN = r"^[0-9a-fA-F-]{36}$"


def event_filter(
    action: Action | None = Query(default=None, description="Exact action name"),
    actor_id: str | None = Query(
        default=None, pattern=ID_PATTERN, description="User or API key id"
    ),
    since: datetime | None = Query(default=None, description="Inclusive; UTC if no offset"),
    until: datetime | None = Query(default=None, description="Exclusive; UTC if no offset"),
) -> EventFilter:
    try:
        since, until = ensure_aware(since), ensure_aware(until)
    except OverflowError as exc:
        raise HTTPException(422, "Date out of range") from exc
    if since is not None and until is not None and since >= until:
        raise HTTPException(422, "since must be before until")
    return EventFilter(action=action, actor_id=actor_id, since=since, until=until)


@router.get("", response_model=AuditEventPage)
def list_audit_events(
    filters: EventFilter = Depends(event_filter),
    cursor: str | None = Query(default=None, description="next_cursor of the previous page"),
    limit: int = Query(default=50, ge=1, le=200),
    ctx: TenantContext = Depends(require("audit:read")),
    db: Session = Depends(get_db),
) -> AuditEventPage:
    try:
        events, next_cursor = audit.list_events(db, ctx.org.id, filters, cursor, limit)
    except audit.InvalidCursor as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return AuditEventPage(
        items=[AuditEventOut.model_validate(event) for event in events], next_cursor=next_cursor
    )
