"""The audit helper: what gets written, and what must never be."""

from __future__ import annotations

from enum import Enum
from types import SimpleNamespace

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError

from saas_auth import audit
from saas_auth.audit import REDACTED, Action, Actor, scrub
from saas_auth.models import AuditEvent, Membership, Organization, User
from saas_auth.security import Principal


@pytest.fixture
def db(app):
    with app.state.session_factory() as session:
        yield session


def add_user(db, email: str, *org_ids: str) -> User:
    user = User(email=email, hashed_password="x")
    db.add(user)
    db.flush()
    for org_id in org_ids:
        db.add(Membership(user_id=user.id, org_id=org_id, role="member"))
    db.flush()
    return user


def add_org(db, slug: str) -> Organization:
    org = Organization(name=slug, slug=slug)
    db.add(org)
    db.flush()
    return org


def events(db) -> list[AuditEvent]:
    db.flush()
    return list(db.scalars(select(AuditEvent)))


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "new_password",
        "client_secret",
        "token",
        "refresh_token",
        "token_hash",
        "hashed_secret",
        "Authorization",
        "cookie",
        "credentials",
        "key",
        "api_key",
    ],
)
def test_scrub_redacts_sensitive_keys(key):
    assert scrub({key: "value"}) == {key: REDACTED}


@pytest.mark.parametrize(
    "value",
    [
        "sk_0a1b2c3d_abcDEF123-_xyz",
        "created with sk_0a1b2c3d_abcDEF123 by mistake",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
        "$2b$12$abcdefghijklmnopqrstuv",
    ],
)
def test_scrub_redacts_credential_shaped_values_under_innocent_keys(value):
    assert scrub({"name": value}) == {"name": REDACTED}


def test_scrub_reaches_nested_values_and_keeps_public_ones():
    given = {"name": "ci", "prefix": "0a1b2c3d", "extra": {"list": [{"token": "t"}, "fine"]}}
    assert scrub(given) == {
        "name": "ci",
        "prefix": "0a1b2c3d",
        "extra": {"list": [{"token": REDACTED}, "fine"]},
    }


def test_scrub_returns_json_safe_values():
    class Colour(Enum):
        RED = "red"

    assert scrub({"a": Colour.RED, "b": ("x", 1, None, True), "c": {3}}) == {
        "a": "red",
        "b": ["x", 1, None, True],
        "c": [3],
    }


def test_record_uses_the_tenant_context(db):
    org = add_org(db, "acme")
    user = add_user(db, "a@acme.com", org.id)
    ctx = SimpleNamespace(org=org, principal=Principal(user=user), ip="203.0.113.9")

    audit.record(db, ctx, Action.MEMBER_REMOVED, ("user", "target-1"), role="viewer")

    event = events(db)[0]
    assert (event.org_id, event.actor_kind, event.actor_id) == (org.id, "user", user.id)
    assert (event.action, event.target_type, event.target_id) == (
        "member.removed",
        "user",
        "target-1",
    )
    assert event.details == {"role": "viewer"}
    assert event.ip == "203.0.113.9"


def test_record_attributes_api_keys_to_the_key_itself(db):
    org = add_org(db, "acme")
    key = SimpleNamespace(id="key-1")
    ctx = SimpleNamespace(org=org, principal=Principal(api_key=key), ip=None)

    audit.record(db, ctx, Action.API_KEY_REVOKED, ("api_key", "key-2"))

    event = events(db)[0]
    assert (event.actor_kind, event.actor_id) == ("api_key", "key-1")


def test_record_scrubs_metadata(db):
    org = add_org(db, "acme")
    audit.record_for_org(
        db, org.id, Actor.system(), Action.API_KEY_CREATED, ("api_key", "k"), token="raw"
    )
    assert events(db)[0].details == {"token": REDACTED}


def test_nothing_is_committed_by_the_helper(app, db):
    org = add_org(db, "acme")
    audit.record_for_org(db, org.id, Actor.system(), Action.ORG_DELETED, ("org", org.id))
    db.rollback()
    assert events(db) == []


def test_account_events_fan_out_to_each_organization(db):
    first, second = add_org(db, "first"), add_org(db, "second")
    user = add_user(db, "a@acme.com", first.id, second.id)

    written = audit.record_for_user(
        db, user.id, Actor.system("203.0.113.9"), Action.USER_LOCKED, ("user", user.id)
    )

    assert {e.org_id for e in written} == {first.id, second.id}
    assert all(e.actor_kind == "system" and e.actor_id is None for e in written)


def test_account_events_without_an_organization_are_stored_unscoped(db):
    user = add_user(db, "loner@acme.com")
    written = audit.record_for_user(db, user.id, Actor.system(), Action.USER_LOCKED, ("user", "u"))
    assert [e.org_id for e in written] == [None]


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_events SET action = 'tampered'",
        "UPDATE audit_events SET org_id = NULL",
        "DELETE FROM audit_events",
    ],
)
def test_database_refuses_to_change_or_remove_events(app, db, statement):
    org = add_org(db, "acme")
    audit.record_for_org(db, org.id, Actor.system(), Action.ORG_DELETED, ("org", org.id))
    db.commit()

    with pytest.raises(DBAPIError, match="append-only"):
        db.execute(text(statement))
    db.rollback()

    assert events(db)[0].action == "org.deleted"


def test_orm_changes_to_a_stored_event_are_refused(db):
    org = add_org(db, "acme")
    event = audit.record_for_org(db, org.id, Actor.system(), Action.ORG_DELETED, ("org", org.id))
    db.commit()

    event.details = {"rewritten": True}
    with pytest.raises(DBAPIError, match="append-only"):
        db.commit()
    db.rollback()

    db.delete(event)
    with pytest.raises(DBAPIError, match="append-only"):
        db.commit()
    db.rollback()


def test_postgres_also_refuses_truncate(app, db):
    if db.get_bind().dialect.name != "postgresql":
        pytest.skip("TRUNCATE only exists on PostgreSQL")
    with pytest.raises(DBAPIError, match="append-only"):
        db.execute(text("TRUNCATE audit_events"))
    db.rollback()
