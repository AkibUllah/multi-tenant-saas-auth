"""Each security-relevant route leaves exactly one audit event, in the same transaction."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from saas_auth import audit
from saas_auth.models import AuditEvent, Membership


def stored_events(app, org_id: str | None = None, action: str | None = None) -> list[AuditEvent]:
    query = select(AuditEvent).order_by(AuditEvent.created_at)
    if org_id is not None:
        query = query.where(AuditEvent.org_id == org_id)
    if action is not None:
        query = query.where(AuditEvent.action == action)
    with app.state.session_factory() as db:
        return list(db.scalars(query))


def user_id(api, tokens: dict) -> str:
    return api.client.get("/v1/auth/me", headers=api.auth(tokens)).json()["id"]


@pytest.fixture
def team(api):
    owner = api.signup("owner@acme.com")
    org = api.create_org(owner, "Acme Ltd")
    viewer = api.invite_and_accept(owner, org["id"], "viewer@acme.com", "viewer")
    return dict(org=org, owner=owner, viewer=viewer, viewer_id=user_id(api, viewer))


def test_role_change_is_recorded(app, api, client, team):
    org_id = team["org"]["id"]
    r = client.patch(
        f"/v1/orgs/{org_id}/members/{team['viewer_id']}",
        json={"role": "admin"},
        headers=api.auth(team["owner"]),
    )
    assert r.status_code == 200

    [event] = stored_events(app, org_id, "member.role_changed")
    assert (event.actor_kind, event.actor_id) == ("user", user_id(api, team["owner"]))
    assert (event.target_type, event.target_id) == ("user", team["viewer_id"])
    assert event.details == {"from_role": "viewer", "to_role": "admin"}
    assert event.ip == "testclient"


def test_setting_the_same_role_records_nothing(app, api, client, team):
    org_id = team["org"]["id"]
    r = client.patch(
        f"/v1/orgs/{org_id}/members/{team['viewer_id']}",
        json={"role": "viewer"},
        headers=api.auth(team["owner"]),
    )
    assert r.status_code == 200
    assert stored_events(app, org_id, "member.role_changed") == []


def test_refused_role_change_records_nothing(app, api, client, team):
    org_id = team["org"]["id"]
    r = client.patch(
        f"/v1/orgs/{org_id}/members/{team['viewer_id']}",
        json={"role": "owner"},
        headers=api.auth(team["viewer"]),
    )
    assert r.status_code == 403
    assert stored_events(app, org_id, "member.role_changed") == []


def test_member_removal_is_recorded(app, api, client, team):
    org_id = team["org"]["id"]
    r = client.delete(
        f"/v1/orgs/{org_id}/members/{team['viewer_id']}", headers=api.auth(team["owner"])
    )
    assert r.status_code == 200

    [event] = stored_events(app, org_id, "member.removed")
    assert event.target_id == team["viewer_id"]
    assert event.details == {"role": "viewer"}


def test_leaving_is_recorded_against_the_member(app, api, client, team):
    org_id = team["org"]["id"]
    r = client.post(f"/v1/orgs/{org_id}/members/leave", headers=api.auth(team["viewer"]))
    assert r.status_code == 200

    [event] = stored_events(app, org_id, "member.left")
    assert event.actor_id == event.target_id == team["viewer_id"]


def test_failed_audit_write_rolls_the_change_back(app, api, team, monkeypatch):
    org_id, viewer_id = team["org"]["id"], team["viewer_id"]

    def explode(*args, **kwargs):
        raise RuntimeError("audit write failed")

    monkeypatch.setattr(audit, "record", explode)
    with TestClient(app, raise_server_exceptions=False) as failing:
        r = failing.delete(
            f"/v1/orgs/{org_id}/members/{viewer_id}", headers=api.auth(team["owner"])
        )
    assert r.status_code == 500

    with app.state.session_factory() as db:
        membership = db.scalar(
            select(Membership).where(Membership.org_id == org_id, Membership.user_id == viewer_id)
        )
    assert membership is not None


def test_failed_commit_leaves_no_event(app, api, client, team, monkeypatch):
    org_id = team["org"]["id"]

    def refuse(self):
        raise RuntimeError("commit failed")

    monkeypatch.setattr("sqlalchemy.orm.Session.commit", refuse)
    with TestClient(app, raise_server_exceptions=False) as failing:
        r = failing.delete(
            f"/v1/orgs/{org_id}/members/{team['viewer_id']}", headers=api.auth(team["owner"])
        )
    monkeypatch.undo()

    assert r.status_code == 500
    assert stored_events(app, org_id, "member.removed") == []
