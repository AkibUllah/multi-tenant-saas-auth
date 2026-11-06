"""Audit log of security events.

Events are added to the caller's session and commit with the change they describe, so a rolled
back action leaves no trace and a committed one cannot lose its record. Nothing here commits.

Metadata passes through `scrub` on the way in. Call sites should never pass a credential in the
first place; the scrubber is the backstop for the day one of them does.
"""

from __future__ import annotations

import base64
import binascii
import logging
import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import TYPE_CHECKING, Any

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from .models import AuditEvent, Membership
from .security import Principal
from .utils import ensure_aware

if TYPE_CHECKING:
    from .rbac import TenantContext

log = logging.getLogger(__name__)

REDACTED = "[REDACTED]"

_SENSITIVE_KEY = re.compile(
    r"pass(word|wd|phrase)|secret|token|hash|authorization|cookie|credential|(^|_)key$",
    re.IGNORECASE,
)
_SENSITIVE_VALUE = re.compile(
    r"\bsk_[0-9a-f]+_[\w-]+"  # API key
    r"|\beyJ[\w-]+\.[\w-]+\.[\w-]+"  # JWT
    r"|\$2[aby]\$\d{2}\$"  # bcrypt hash
)


class Action(str, Enum):
    MEMBER_ROLE_CHANGED = "member.role_changed"
    MEMBER_REMOVED = "member.removed"
    MEMBER_LEFT = "member.left"
    INVITATION_CREATED = "invitation.created"
    INVITATION_REVOKED = "invitation.revoked"
    INVITATION_ACCEPTED = "invitation.accepted"
    API_KEY_CREATED = "api_key.created"
    API_KEY_REVOKED = "api_key.revoked"
    USER_LOCKED = "user.locked"
    ORG_DELETED = "org.deleted"
    AUDIT_EXPORTED = "audit.exported"


@dataclass(frozen=True)
class Actor:
    """Who an event is attributed to, for code paths without a TenantContext."""

    kind: str
    id: str | None = None
    ip: str | None = None

    @classmethod
    def of(cls, principal: Principal, ip: str | None = None) -> Actor:
        return cls(kind=principal.kind, id=principal.id, ip=ip)

    @classmethod
    def system(cls, ip: str | None = None) -> Actor:
        """The service acting on its own, such as a lockout triggered by anonymous requests."""
        return cls(kind="system", ip=ip)


def scrub(value: Any) -> Any:
    """Return a JSON-safe copy of `value` with anything credential-shaped replaced."""
    if isinstance(value, Mapping):
        cleaned = {}
        for key, item in value.items():
            if _SENSITIVE_KEY.search(str(key)):
                log.warning("redacted audit metadata key %r", str(key))
                cleaned[str(key)] = REDACTED
            else:
                cleaned[str(key)] = scrub(item)
        return cleaned
    if isinstance(value, (list, tuple, set, frozenset)):
        return [scrub(item) for item in value]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    text = value.value if isinstance(value, Enum) else str(value)
    return REDACTED if _SENSITIVE_VALUE.search(text) else text


def _add(
    db: Session,
    org_id: str | None,
    actor: Actor,
    action: Action,
    target: tuple[str, str | None],
    details: dict[str, Any],
) -> AuditEvent:
    target_type, target_id = target
    event = AuditEvent(
        org_id=org_id,
        actor_kind=actor.kind,
        actor_id=actor.id,
        action=action.value,
        target_type=target_type,
        target_id=target_id,
        details=scrub(details),
        ip=actor.ip[:45] if actor.ip else None,
    )
    db.add(event)
    return event


def record(
    db: Session,
    ctx: TenantContext,
    action: Action,
    target: tuple[str, str | None],
    /,
    **meta: Any,
) -> AuditEvent:
    """Record `action` inside the organization the request is acting on."""
    return _add(db, ctx.org.id, Actor.of(ctx.principal, ctx.ip), action, target, meta)


def record_for_org(
    db: Session,
    org_id: str,
    actor: Actor,
    action: Action,
    target: tuple[str, str | None],
    /,
    **meta: Any,
) -> AuditEvent:
    """Record `action` for an organization when the request has no tenant in its path."""
    return _add(db, org_id, actor, action, target, meta)


def record_for_user(
    db: Session,
    user_id: str,
    actor: Actor,
    action: Action,
    target: tuple[str, str | None],
    /,
    **meta: Any,
) -> list[AuditEvent]:
    """Record an account-level event once in every organization the user belongs to.

    A login belongs to no tenant, so each organization gets its own row and sees the event about
    its member without learning which other organizations that person is in. A user with no
    memberships gets a single row with a NULL org_id, which no organization can read.
    """
    org_ids = db.scalars(select(Membership.org_id).where(Membership.user_id == user_id)).all()
    return [_add(db, org_id, actor, action, target, meta) for org_id in org_ids or [None]]


# --------------------------------------------------------------------------- reading


class InvalidCursor(ValueError):
    """The pagination cursor was not one this service issued."""


@dataclass(frozen=True)
class EventFilter:
    action: Action | None = None
    actor_id: str | None = None
    since: datetime | None = None  # inclusive
    until: datetime | None = None  # exclusive


def encode_cursor(event: AuditEvent) -> str:
    raw = f"{event.created_at.isoformat()}|{event.id}"
    return base64.urlsafe_b64encode(raw.encode()).decode()


def decode_cursor(cursor: str) -> tuple[datetime, str]:
    try:
        created_at, event_id = base64.urlsafe_b64decode(cursor).decode().split("|")
        return ensure_aware(datetime.fromisoformat(created_at)), str(uuid.UUID(event_id))
    except (ValueError, OverflowError, binascii.Error) as exc:
        raise InvalidCursor("Invalid cursor") from exc


def list_events(
    db: Session,
    org_id: str,
    filters: EventFilter,
    cursor: str | None = None,
    limit: int = 50,
) -> tuple[list[AuditEvent], str | None]:
    """One page of an organization's events, newest first, plus the cursor for the next page.

    Paging is keyset on (created_at, id), so it stays cheap on deep pages and does not shift when
    new events arrive. The cursor only says where to resume: `org_id` is always applied, so a
    cursor taken from another organization cannot widen what is returned.
    """
    query = select(AuditEvent).where(AuditEvent.org_id == org_id)
    if filters.action is not None:
        query = query.where(AuditEvent.action == filters.action.value)
    if filters.actor_id is not None:
        query = query.where(AuditEvent.actor_id == filters.actor_id)
    if filters.since is not None:
        query = query.where(AuditEvent.created_at >= filters.since)
    if filters.until is not None:
        query = query.where(AuditEvent.created_at < filters.until)
    if cursor is not None:
        created_at, event_id = decode_cursor(cursor)
        query = query.where(
            or_(
                AuditEvent.created_at < created_at,
                and_(AuditEvent.created_at == created_at, AuditEvent.id < event_id),
            )
        )
    query = query.order_by(AuditEvent.created_at.desc(), AuditEvent.id.desc()).limit(limit + 1)

    rows = list(db.scalars(query))
    page = rows[:limit]
    return page, encode_cursor(page[-1]) if len(rows) > limit else None
