from __future__ import annotations

import pytest

from saas_auth.security import generate_api_key, parse_api_key


def test_generate_and_parse_api_key():
    raw, prefix, hashed = generate_api_key()
    assert raw.startswith("sk_")
    parsed = parse_api_key(raw)
    assert parsed is not None and parsed[0] == prefix
    assert len(hashed) == 64
    assert parse_api_key("garbage") is None
    assert parse_api_key("sk__") is None


@pytest.fixture
def org(api):
    owner = api.signup("keys@example.com")
    org = api.create_org(owner, "Key Co")
    return owner, org


def test_create_key_returns_secret_once_and_lists_without_it(api, client, org):
    owner, org = org
    r = client.post(
        f"/v1/orgs/{org['id']}/api-keys",
        json={"name": "deploy bot", "scopes": ["projects:read", "projects:create"]},
        headers=api.auth(owner),
    )
    assert r.status_code == 201
    created = r.json()
    assert created["key"].startswith(f"sk_{created['prefix']}_")
    assert created["scopes"] == ["projects:create", "projects:read"]

    listed = client.get(f"/v1/orgs/{org['id']}/api-keys", headers=api.auth(owner)).json()
    assert len(listed) == 1
    assert "key" not in listed[0]
    assert listed[0]["prefix"] == created["prefix"]


def test_key_scopes_are_enforced_and_last_used_updates(api, client, org):
    owner, org = org
    key = client.post(
        f"/v1/orgs/{org['id']}/api-keys",
        json={"name": "reader", "scopes": ["projects:read"]},
        headers=api.auth(owner),
    ).json()["key"]
    headers = {"X-API-Key": key}
    url = f"/v1/orgs/{org['id']}/projects"
    assert client.get(url, headers=headers).status_code == 200
    r = client.post(url, json={"name": "nope"}, headers=headers)
    assert r.status_code == 403

    listed = client.get(f"/v1/orgs/{org['id']}/api-keys", headers=api.auth(owner)).json()
    assert listed[0]["last_used_at"] is not None


def test_unknown_scope_and_scope_escalation_rejected(api, client, org):
    owner, org = org
    r = client.post(
        f"/v1/orgs/{org['id']}/api-keys",
        json={"name": "bad", "scopes": ["universe:admin"]},
        headers=api.auth(owner),
    )
    assert r.status_code == 422

    admin = api.invite_and_accept(owner, org["id"], "admin@keyco.com", "admin")
    r = client.post(
        f"/v1/orgs/{org['id']}/api-keys",
        json={"name": "too-broad", "scopes": ["org:delete"]},
        headers=api.auth(admin),
    )
    assert r.status_code == 403
    assert r.json()["detail"]["scopes"] == ["org:delete"]


def test_revoked_key_and_wrong_secret_fail(api, client, org):
    owner, org = org
    created = client.post(
        f"/v1/orgs/{org['id']}/api-keys",
        json={"name": "temp", "scopes": ["projects:read"]},
        headers=api.auth(owner),
    ).json()
    url = f"/v1/orgs/{org['id']}/projects"

    tampered = created["key"][:-4] + "zzzz"
    assert client.get(url, headers={"X-API-Key": tampered}).status_code == 401

    r = client.delete(f"/v1/orgs/{org['id']}/api-keys/{created['id']}", headers=api.auth(owner))
    assert r.status_code == 200
    assert client.get(url, headers={"X-API-Key": created["key"]}).status_code == 401


def test_api_key_cannot_mint_keys_or_act_as_user(api, client, org):
    owner, org = org
    key = client.post(
        f"/v1/orgs/{org['id']}/api-keys",
        json={"name": "full", "scopes": ["api_keys:create", "org:read"]},
        headers=api.auth(owner),
    ).json()["key"]
    headers = {"X-API-Key": key}
    r = client.post(
        f"/v1/orgs/{org['id']}/api-keys",
        json={"name": "child", "scopes": ["org:read"]},
        headers=headers,
    )
    assert r.status_code == 403
    assert client.get("/v1/auth/me", headers=headers).status_code == 403
    r = client.get(f"/v1/orgs/{org['id']}", headers=headers)
    assert r.status_code == 200 and r.json()["role"] == "api_key"


def test_generated_keys_always_round_trip_through_the_parser():
    from saas_auth.security import generate_api_key, hash_token, parse_api_key

    for _ in range(2000):
        raw, prefix, secret_hash = generate_api_key()
        parsed = parse_api_key(raw)
        assert parsed is not None, raw
        assert parsed[0] == prefix
        assert hash_token(parsed[1]) == secret_hash
