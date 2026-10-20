from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select

from saas_auth.models import Invitation


@pytest.fixture
def org(api):
    owner = api.signup("boss@startup.bd")
    return owner, api.create_org(owner, "Startup BD")


def test_invite_sends_email_and_accept_creates_membership(api, client, org, outbox):
    owner, org = org
    r = client.post(
        f"/v1/orgs/{org['id']}/invitations",
        json={"email": "Nadia@Startup.bd", "role": "member"},
        headers=api.auth(owner),
    )
    assert r.status_code == 201
    inv = r.json()
    assert inv["email"] == "nadia@startup.bd"
    assert inv["accepted_at"] is None

    message = outbox[-1]
    assert message.to == "nadia@startup.bd"
    assert message.context["kind"] == "invitation" and "Startup BD" in message.subject

    nadia = api.signup("nadia@startup.bd")
    r = client.post(
        "/v1/invitations/accept",
        json={"token": message.context["token"]},
        headers=api.auth(nadia),
    )
    assert r.status_code == 200
    assert r.json() == {
        "org": {k: org[k] for k in ("id", "name", "slug", "created_at")},
        "role": "member",
    }

    members = client.get(f"/v1/orgs/{org['id']}/members", headers=api.auth(owner)).json()
    assert {m["email"]: m["role"] for m in members} == {
        "boss@startup.bd": "owner",
        "nadia@startup.bd": "member",
    }
    # Token is single use.
    r = client.post(
        "/v1/invitations/accept",
        json={"token": message.context["token"]},
        headers=api.auth(nadia),
    )
    assert r.status_code == 400


def test_accept_with_different_email_is_forbidden(api, client, org, outbox):
    owner, org = org
    client.post(
        f"/v1/orgs/{org['id']}/invitations",
        json={"email": "intended@startup.bd", "role": "viewer"},
        headers=api.auth(owner),
    )
    token = outbox[-1].context["token"]
    impostor = api.signup("impostor@evil.com")
    r = client.post("/v1/invitations/accept", json={"token": token}, headers=api.auth(impostor))
    assert r.status_code == 403
    assert client.get(f"/v1/orgs/{org['id']}", headers=api.auth(impostor)).status_code == 404


def test_duplicate_pending_invite_and_existing_member_conflict(api, client, org):
    owner, org = org
    url = f"/v1/orgs/{org['id']}/invitations"
    body = {"email": "twice@startup.bd", "role": "member"}
    assert client.post(url, json=body, headers=api.auth(owner)).status_code == 201
    assert client.post(url, json=body, headers=api.auth(owner)).status_code == 409

    body = {"email": "boss@startup.bd", "role": "member"}
    assert client.post(url, json=body, headers=api.auth(owner)).status_code == 409


def test_admin_cannot_invite_owner(api, client, org):
    owner, org = org
    admin = api.invite_and_accept(owner, org["id"], "admin@startup.bd", "admin")
    r = client.post(
        f"/v1/orgs/{org['id']}/invitations",
        json={"email": "newowner@startup.bd", "role": "owner"},
        headers=api.auth(admin),
    )
    assert r.status_code == 403


def test_revoked_invitation_cannot_be_accepted(api, client, org, outbox):
    owner, org = org
    inv = client.post(
        f"/v1/orgs/{org['id']}/invitations",
        json={"email": "late@startup.bd", "role": "member"},
        headers=api.auth(owner),
    ).json()
    token = outbox[-1].context["token"]
    r = client.delete(f"/v1/orgs/{org['id']}/invitations/{inv['id']}", headers=api.auth(owner))
    assert r.status_code == 200

    listed = client.get(f"/v1/orgs/{org['id']}/invitations", headers=api.auth(owner)).json()
    assert listed[0]["revoked_at"] is not None

    late = api.signup("late@startup.bd")
    r = client.post("/v1/invitations/accept", json={"token": token}, headers=api.auth(late))
    assert r.status_code == 400


def test_expired_invitation_rejected(api, client, app, org, outbox):
    owner, org = org
    client.post(
        f"/v1/orgs/{org['id']}/invitations",
        json={"email": "slow@startup.bd", "role": "member"},
        headers=api.auth(owner),
    )
    token = outbox[-1].context["token"]
    with app.state.session_factory() as db:
        inv = db.scalars(select(Invitation)).one()
        inv.expires_at = datetime.now(timezone.utc) - timedelta(minutes=1)
        db.commit()
    slow = api.signup("slow@startup.bd")
    r = client.post("/v1/invitations/accept", json={"token": token}, headers=api.auth(slow))
    assert r.status_code == 400
