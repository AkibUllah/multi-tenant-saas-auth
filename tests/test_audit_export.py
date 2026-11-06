"""CSV export of the audit log, and the end-to-end guarantee that no secret reaches it."""

from __future__ import annotations

import csv
import io
import json

import pytest
from sqlalchemy import select

from saas_auth import audit
from saas_auth.audit import CSV_COLUMNS, Action, Actor, csv_safe
from saas_auth.models import ApiKey, AuditEvent, Invitation, User
from tests.conftest import Api


def export_url(org_id: str) -> str:
    return f"/v1/orgs/{org_id}/audit-events/export.csv"


def rows(response) -> list[dict]:
    return list(csv.DictReader(io.StringIO(response.text)))


@pytest.fixture
def team(api):
    owner = api.signup("owner@acme.com")
    org = api.create_org(owner, "Acme Ltd")
    admin = api.invite_and_accept(owner, org["id"], "admin@acme.com", "admin")
    viewer = api.invite_and_accept(owner, org["id"], "viewer@acme.com", "viewer")
    return dict(org=org, owner=owner, admin=admin, viewer=viewer)


def test_export_is_a_downloadable_csv(api, client, team):
    r = client.get(export_url(team["org"]["id"]), headers=api.auth(team["owner"]))
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert r.headers["content-disposition"] == 'attachment; filename="audit-events-acme-ltd.csv"'
    assert r.text.splitlines()[0].split(",") == list(CSV_COLUMNS)


def test_export_matches_the_list_endpoint(api, client, team):
    org_id = team["org"]["id"]
    headers = api.auth(team["owner"])
    exported = rows(client.get(export_url(org_id), headers=headers))
    listed = client.get(f"/v1/orgs/{org_id}/audit-events", headers=headers).json()["items"]

    assert [r["id"] for r in exported] == [e["id"] for e in listed]
    assert json.loads(exported[-1]["metadata"]) == listed[-1]["metadata"]


def test_export_is_itself_recorded_with_its_filters(api, client, team):
    org_id = team["org"]["id"]
    headers = api.auth(team["owner"])
    params = {"action": "invitation.created", "since": "2026-01-01T00:00:00"}
    assert client.get(export_url(org_id), params=params, headers=headers).status_code == 200

    r = client.get(
        f"/v1/orgs/{org_id}/audit-events", params={"action": "audit.exported"}, headers=headers
    )
    [event] = r.json()["items"]
    assert event["metadata"] == {
        "action": "invitation.created",
        "since": "2026-01-01 00:00:00+00:00",
    }


def test_export_applies_filters(api, client, team):
    r = client.get(
        export_url(team["org"]["id"]),
        params={"action": "invitation.accepted"},
        headers=api.auth(team["owner"]),
    )
    assert {row["action"] for row in rows(r)} == {"invitation.accepted"}
    assert len(rows(r)) == 2


def test_export_walks_past_a_batch_boundary(app, api, client, team, monkeypatch):
    org_id = team["org"]["id"]
    with app.state.session_factory() as db:
        for _ in range(5):
            audit.record_for_org(db, org_id, Actor.system(), Action.ORG_DELETED, ("org", org_id))
        db.commit()
    monkeypatch.setattr(audit, "EXPORT_BATCH_SIZE", 2)

    exported = rows(client.get(export_url(org_id), headers=api.auth(team["owner"])))

    assert len({row["id"] for row in exported}) == len(exported) >= 5


def test_export_requires_audit_read(api, client, team):
    r = client.get(export_url(team["org"]["id"]), headers=api.auth(team["viewer"]))
    assert r.status_code == 403
    assert client.get(export_url(team["org"]["id"])).status_code == 401


def test_export_never_crosses_organizations(api, client, team):
    outsider = api.signup("outsider@globex.com")
    globex = api.create_org(outsider, "Globex")

    r = client.get(export_url(team["org"]["id"]), headers=api.auth(outsider))
    assert r.status_code == 404
    r = client.get(export_url(globex["id"]), headers=api.auth(outsider))
    assert [row["action"] for row in rows(r)] == ["audit.exported"]


@pytest.mark.parametrize("payload", ["=1+1", "+1", "-1", "@SUM(A1)", "\t=1", "\r=1", "\n=1"])
def test_formula_prefixes_are_neutralised(payload):
    assert csv_safe(payload) == f"'{payload}"


def test_ordinary_values_are_untouched():
    assert csv_safe("member.removed") == "member.removed"
    assert csv_safe("") == ""
    assert csv_safe('{"a": "=1"}') == '{"a": "=1"}'


def test_no_exported_cell_can_be_read_as_a_formula(api, client, team):
    org_id = team["org"]["id"]
    headers = api.auth(team["owner"])
    client.post(
        f"/v1/orgs/{org_id}/api-keys",
        json={"name": '=HYPERLINK("http://evil.test","x")', "scopes": []},
        headers=headers,
    )
    r = client.get(export_url(org_id), headers=headers)

    assert "HYPERLINK" in r.text
    for row in rows(r):
        assert not any(cell[:1] in ("=", "+", "-", "@") for cell in row.values())


def test_no_secret_survives_into_the_log(app, api: Api, client, team):
    """Drive every recorded action and search all of what the log stores and serves."""
    org_id = team["org"]["id"]
    headers = api.auth(team["owner"])
    password = "correct-horse-battery"

    created = client.post(
        f"/v1/orgs/{org_id}/api-keys",
        json={"name": "ci", "scopes": ["audit:read"]},
        headers=headers,
    ).json()
    client.delete(f"/v1/orgs/{org_id}/api-keys/{created['id']}", headers=headers)
    invited = client.post(
        f"/v1/orgs/{org_id}/invitations",
        json={"email": "new@acme.com", "role": "member"},
        headers=headers,
    ).json()
    client.delete(f"/v1/orgs/{org_id}/invitations/{invited['id']}", headers=headers)
    client.post(
        f"/v1/orgs/{org_id}/invitations",
        json={"email": "late@acme.com", "role": "member"},
        headers=headers,
    )
    invitation_token = app.state.email.last_for("late@acme.com").context["token"]
    late = api.signup("late@acme.com")
    accepted = client.post(
        "/v1/invitations/accept", json={"token": invitation_token}, headers=api.auth(late)
    )
    assert accepted.status_code == 200
    for _ in range(3):
        client.post("/v1/auth/login", json={"email": "viewer@acme.com", "password": "wrong-pass"})

    with app.state.session_factory() as db:
        stored = list(db.scalars(select(AuditEvent)))
        secrets = [
            password,
            "wrong-pass",
            created["key"],
            created["key"].split("_", 2)[2],
            team["owner"]["access_token"],
            team["owner"]["refresh_token"],
            late["refresh_token"],
            invitation_token,
        ]
        secrets += list(db.scalars(select(User.hashed_password)))
        secrets += list(db.scalars(select(ApiKey.hashed_secret)))
        secrets += list(db.scalars(select(Invitation.token_hash)))

    assert stored
    columns = AuditEvent.__table__.columns.keys()
    dump = json.dumps(
        [[str(getattr(e, c.replace("metadata", "details"))) for c in columns] for e in stored]
    )
    served = client.get(f"/v1/orgs/{org_id}/audit-events?limit=200", headers=headers).text
    exported = client.get(export_url(org_id), headers=headers).text

    for secret in secrets:
        assert secret not in dump
        assert secret not in served
        assert secret not in exported
