from __future__ import annotations

from datetime import timedelta

from saas_auth.security import create_access_token, hash_password, verify_password


def test_password_hash_roundtrip():
    hashed = hash_password("s3cret-pass", rounds=4)
    assert hashed != "s3cret-pass"
    assert verify_password("s3cret-pass", hashed)
    assert not verify_password("wrong", hashed)


def test_register_login_me(api, client):
    user = api.register("rahim@example.com", name="Rahim Uddin")
    assert user["email"] == "rahim@example.com"
    assert user["is_verified"] is False

    tokens = api.login("rahim@example.com")
    assert tokens["token_type"] == "bearer"
    assert tokens["expires_in"] > 0

    r = client.get("/v1/auth/me", headers=api.auth(tokens))
    assert r.status_code == 200
    assert r.json()["full_name"] == "Rahim Uddin"


def test_register_duplicate_email_conflicts(api, client):
    api.register("dup@example.com")
    r = client.post(
        "/v1/auth/register", json={"email": "Dup@Example.com", "password": "another-pass-1"}
    )
    assert r.status_code == 409


def test_register_rejects_short_password(client):
    r = client.post("/v1/auth/register", json={"email": "x@example.com", "password": "short"})
    assert r.status_code == 422


def test_login_wrong_password_and_unknown_user(api, client):
    api.register("karim@example.com")
    r = client.post("/v1/auth/login", json={"email": "karim@example.com", "password": "nope-nope"})
    assert r.status_code == 401
    r = client.post("/v1/auth/login", json={"email": "ghost@example.com", "password": "nope-nope"})
    assert r.status_code == 401


def test_me_requires_auth_and_rejects_garbage(client):
    assert client.get("/v1/auth/me").status_code == 401
    r = client.get("/v1/auth/me", headers={"Authorization": "Bearer not-a-jwt"})
    assert r.status_code == 401


def test_expired_access_token_rejected(api, client, settings):
    user = api.register("exp@example.com")
    token = create_access_token(user["id"], settings, expires_delta=timedelta(seconds=-5))
    r = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json()["detail"] == "Token expired"


def test_token_signed_with_other_secret_rejected(api, client, settings):
    user = api.register("sig@example.com")
    other = settings.model_copy(update={"jwt_secret": "someone-elses-secret"})
    token = create_access_token(user["id"], other)
    r = client.get("/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401


def test_email_verification_flow(api, client, outbox):
    api.register("verify@example.com")
    message = outbox[-1]
    assert message.to == "verify@example.com"
    assert message.context["kind"] == "verify"

    r = client.post("/v1/auth/verify-email", json={"token": message.context["token"]})
    assert r.status_code == 200

    tokens = api.login("verify@example.com")
    assert client.get("/v1/auth/me", headers=api.auth(tokens)).json()["is_verified"] is True

    # Single use.
    r = client.post("/v1/auth/verify-email", json={"token": message.context["token"]})
    assert r.status_code == 400


def test_password_reset_flow_revokes_sessions(api, client, outbox):
    tokens = api.signup("reset@example.com")

    r = client.post("/v1/auth/forgot-password", json={"email": "reset@example.com"})
    assert r.status_code == 202
    # Unknown emails get the same answer.
    r = client.post("/v1/auth/forgot-password", json={"email": "nobody@example.com"})
    assert r.status_code == 202

    reset_token = outbox[-1].context["token"]
    assert outbox[-1].context["kind"] == "reset"
    r = client.post(
        "/v1/auth/reset-password", json={"token": reset_token, "new_password": "brand-new-pass"}
    )
    assert r.status_code == 200

    # Old password fails, new one works, old refresh token is dead.
    r = client.post(
        "/v1/auth/login", json={"email": "reset@example.com", "password": "correct-horse-battery"}
    )
    assert r.status_code == 401
    api.login("reset@example.com", "brand-new-pass")
    r = client.post("/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 401


def test_change_password_requires_current(api, client):
    tokens = api.signup("chg@example.com")
    r = client.post(
        "/v1/auth/change-password",
        json={"current_password": "wrong-one", "new_password": "new-password-1"},
        headers=api.auth(tokens),
    )
    assert r.status_code == 400
    r = client.post(
        "/v1/auth/change-password",
        json={"current_password": "correct-horse-battery", "new_password": "new-password-1"},
        headers=api.auth(tokens),
    )
    assert r.status_code == 200
    api.login("chg@example.com", "new-password-1")


def test_health_and_permissions_endpoints(client):
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["database"] == "ok"
    assert body["rate_limiter"] == "memory"
    assert "X-Request-ID" in r.headers

    roles = client.get("/v1/permissions").json()["roles"]
    assert set(roles) == {"owner", "admin", "member", "viewer"}
    assert "org:delete" in roles["owner"] and "org:delete" not in roles["admin"]
