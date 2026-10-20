"""Tenant isolation: everything is scoped by org_id; knowing an id is never enough."""

from __future__ import annotations

import pytest


@pytest.fixture
def two_orgs(api, client):
    alice = api.signup("alice@orga.com")
    bob = api.signup("bob@orgb.com")
    org_a = api.create_org(alice, "Org A")
    org_b = api.create_org(bob, "Org B")
    pa = client.post(
        f"/v1/orgs/{org_a['id']}/projects", json={"name": "A-secret"}, headers=api.auth(alice)
    ).json()
    pb = client.post(
        f"/v1/orgs/{org_b['id']}/projects", json={"name": "B-secret"}, headers=api.auth(bob)
    ).json()
    return dict(alice=alice, bob=bob, org_a=org_a, org_b=org_b, pa=pa, pb=pb)


def test_user_cannot_see_other_org_at_all(api, client, two_orgs):
    alice, org_b = two_orgs["alice"], two_orgs["org_b"]
    assert client.get(f"/v1/orgs/{org_b['id']}", headers=api.auth(alice)).status_code == 404
    assert (
        client.get(f"/v1/orgs/{org_b['id']}/projects", headers=api.auth(alice)).status_code == 404
    )
    assert client.get(f"/v1/orgs/{org_b['id']}/members", headers=api.auth(alice)).status_code == 404


def test_project_id_from_other_org_is_not_reachable_via_own_org(api, client, two_orgs):
    alice, org_a, pb = two_orgs["alice"], two_orgs["org_a"], two_orgs["pb"]
    # Alice uses her own org id but Bob's project id.
    r = client.get(f"/v1/orgs/{org_a['id']}/projects/{pb['id']}", headers=api.auth(alice))
    assert r.status_code == 404
    r = client.patch(
        f"/v1/orgs/{org_a['id']}/projects/{pb['id']}",
        json={"name": "pwned"},
        headers=api.auth(alice),
    )
    assert r.status_code == 404
    r = client.delete(f"/v1/orgs/{org_a['id']}/projects/{pb['id']}", headers=api.auth(alice))
    assert r.status_code == 404


def test_listings_only_contain_own_tenant_rows(api, client, two_orgs):
    alice, bob = two_orgs["alice"], two_orgs["bob"]
    org_a, org_b = two_orgs["org_a"], two_orgs["org_b"]
    names_a = [
        p["name"]
        for p in client.get(f"/v1/orgs/{org_a['id']}/projects", headers=api.auth(alice)).json()
    ]
    names_b = [
        p["name"]
        for p in client.get(f"/v1/orgs/{org_b['id']}/projects", headers=api.auth(bob)).json()
    ]
    assert names_a == ["A-secret"]
    assert names_b == ["B-secret"]

    my_orgs = client.get("/v1/orgs", headers=api.auth(alice)).json()
    assert [o["slug"] for o in my_orgs] == ["org-a"]
    assert my_orgs[0]["role"] == "owner"


def test_api_key_is_pinned_to_its_org(api, client, two_orgs):
    alice, org_a, org_b = two_orgs["alice"], two_orgs["org_a"], two_orgs["org_b"]
    r = client.post(
        f"/v1/orgs/{org_a['id']}/api-keys",
        json={"name": "ci", "scopes": ["projects:read"]},
        headers=api.auth(alice),
    )
    key = r.json()["key"]
    ok = client.get(f"/v1/orgs/{org_a['id']}/projects", headers={"X-API-Key": key})
    assert ok.status_code == 200 and ok.json()[0]["name"] == "A-secret"
    cross = client.get(f"/v1/orgs/{org_b['id']}/projects", headers={"X-API-Key": key})
    assert cross.status_code == 404


def test_same_user_different_roles_in_different_orgs(api, client, two_orgs):
    alice, bob, org_b = two_orgs["alice"], two_orgs["bob"], two_orgs["org_b"]
    # Invite manually (not via the helper) because alice already has an account.
    r = client.post(
        f"/v1/orgs/{org_b['id']}/invitations",
        json={"email": "alice@orga.com", "role": "viewer"},
        headers=api.auth(bob),
    )
    token = client.app.state.email.last_for("alice@orga.com").context["token"]
    r = client.post("/v1/invitations/accept", json={"token": token}, headers=api.auth(alice))
    assert r.status_code == 200 and r.json()["role"] == "viewer"

    roles = {o["slug"]: o["role"] for o in client.get("/v1/orgs", headers=api.auth(alice)).json()}
    assert roles == {"org-a": "owner", "org-b": "viewer"}
    # Viewer in B: can read, cannot create.
    assert (
        client.get(f"/v1/orgs/{org_b['id']}/projects", headers=api.auth(alice)).status_code == 200
    )
    r = client.post(f"/v1/orgs/{org_b['id']}/projects", json={"name": "x"}, headers=api.auth(alice))
    assert r.status_code == 403
