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


def create_key(api, client, tokens, org_id, name="ci", scopes=("members:remove",)) -> dict:
    r = client.post(
        f"/v1/orgs/{org_id}/api-keys",
        json={"name": name, "scopes": list(scopes)},
        headers=api.auth(tokens),
    )
    assert r.status_code == 201, r.text
    return r.json()


def test_api_key_creation_is_recorded_without_the_secret(app, api, client, team):
    org_id = team["org"]["id"]
    key = create_key(api, client, team["owner"], org_id)

    [event] = stored_events(app, org_id, "api_key.created")
    assert (event.target_type, event.target_id) == ("api_key", key["id"])
    assert event.details == {"name": "ci", "prefix": key["prefix"], "scopes": ["members:remove"]}


def test_api_key_revocation_is_recorded_once(app, api, client, team):
    org_id = team["org"]["id"]
    key = create_key(api, client, team["owner"], org_id)
    url = f"/v1/orgs/{org_id}/api-keys/{key['id']}"

    assert client.delete(url, headers=api.auth(team["owner"])).status_code == 200
    assert client.delete(url, headers=api.auth(team["owner"])).status_code == 200

    [event] = stored_events(app, org_id, "api_key.revoked")
    assert event.target_id == key["id"]


def test_action_taken_with_an_api_key_is_attributed_to_that_key(app, api, client, team):
    org_id = team["org"]["id"]
    key = create_key(api, client, team["owner"], org_id)

    r = client.delete(
        f"/v1/orgs/{org_id}/members/{team['viewer_id']}", headers={"X-API-Key": key["key"]}
    )
    assert r.status_code == 200

    [event] = stored_events(app, org_id, "member.removed")
    assert (event.actor_kind, event.actor_id) == ("api_key", key["id"])


def invite(api, client, tokens, org_id, email="new@acme.com", role="member") -> dict:
    r = client.post(
        f"/v1/orgs/{org_id}/invitations",
        json={"email": email, "role": role},
        headers=api.auth(tokens),
    )
    assert r.status_code == 201, r.text
    return r.json()


def test_invitation_creation_is_recorded(app, api, client, team):
    org_id = team["org"]["id"]
    invitation = invite(api, client, team["owner"], org_id)

    event = stored_events(app, org_id, "invitation.created")[-1]
    assert (event.target_type, event.target_id) == ("invitation", invitation["id"])
    assert event.details == {"email": "new@acme.com", "role": "member"}


def test_invitation_revocation_is_recorded_once(app, api, client, team):
    org_id = team["org"]["id"]
    invitation = invite(api, client, team["owner"], org_id)
    url = f"/v1/orgs/{org_id}/invitations/{invitation['id']}"

    assert client.delete(url, headers=api.auth(team["owner"])).status_code == 200
    assert client.delete(url, headers=api.auth(team["owner"])).status_code == 200

    [event] = stored_events(app, org_id, "invitation.revoked")
    assert event.target_id == invitation["id"]


def test_invitation_acceptance_is_recorded_against_the_invitee(app, api, team):
    org_id = team["org"]["id"]
    [event] = stored_events(app, org_id, "invitation.accepted")
    assert org_id == event.org_id
    assert (event.actor_kind, event.actor_id) == ("user", team["viewer_id"])
    assert event.details == {"email": "viewer@acme.com", "role": "viewer"}


def lock_out(client, settings, email: str) -> None:
    body = {"email": email, "password": "wrong-password"}
    for _ in range(settings.login_max_attempts):
        assert client.post("/v1/auth/login", json=body).status_code == 401


def test_lockout_reaches_every_organization_of_the_user(app, api, client, settings, team):
    other_owner = api.signup("other@globex.com")
    other_org = api.create_org(other_owner, "Globex")
    r = client.post(
        f"/v1/orgs/{other_org['id']}/invitations",
        json={"email": "viewer@acme.com", "role": "viewer"},
        headers=api.auth(other_owner),
    )
    assert r.status_code == 201
    token = app.state.email.last_for("viewer@acme.com").context["token"]
    r = client.post(
        "/v1/invitations/accept", json={"token": token}, headers=api.auth(team["viewer"])
    )
    assert r.status_code == 200

    lock_out(client, settings, "viewer@acme.com")

    events = stored_events(app, action="user.locked")
    assert {e.org_id for e in events} == {team["org"]["id"], other_org["id"]}
    for event in events:
        assert (event.actor_kind, event.actor_id) == ("system", None)
        assert (event.target_type, event.target_id) == ("user", team["viewer_id"])
        assert event.details == {"lockout_seconds": settings.login_lockout_seconds}


def test_lockout_of_a_user_without_organizations_stays_unscoped(app, api, client, settings):
    api.register("solo@example.com")
    lock_out(client, settings, "solo@example.com")
    assert [e.org_id for e in stored_events(app, action="user.locked")] == [None]


def test_failed_logins_below_the_threshold_record_nothing(app, api, client, team):
    r = client.post(
        "/v1/auth/login", json={"email": "viewer@acme.com", "password": "wrong-password"}
    )
    assert r.status_code == 401
    assert stored_events(app, action="user.locked") == []


def test_org_deletion_is_recorded_and_the_log_outlives_the_org(app, api, client, team):
    org_id = team["org"]["id"]
    assert client.delete(f"/v1/orgs/{org_id}", headers=api.auth(team["owner"])).status_code == 200

    [event] = stored_events(app, org_id, "org.deleted")
    assert event.details == {"name": "Acme Ltd", "slug": "acme-ltd"}
    assert stored_events(app, org_id, "invitation.accepted")
