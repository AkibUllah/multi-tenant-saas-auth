from __future__ import annotations

from sqlalchemy import select

from saas_auth.models import RefreshToken


def _refresh(client, token: str):
    return client.post("/v1/auth/refresh", json={"refresh_token": token})


def test_refresh_rotates_and_old_token_stops_working(api, client):
    t1 = api.signup("rot@example.com")
    r = _refresh(client, t1["refresh_token"])
    assert r.status_code == 200
    t2 = r.json()
    assert t2["refresh_token"] != t1["refresh_token"]
    assert t2["access_token"]

    # New token works, access token is valid.
    assert client.get("/v1/auth/me", headers=api.auth(t2)).status_code == 200


def test_reuse_of_rotated_token_revokes_whole_family(api, client, app):
    t1 = api.signup("reuse@example.com")
    t2 = _refresh(client, t1["refresh_token"]).json()
    t3 = _refresh(client, t2["refresh_token"]).json()

    # Attacker replays t1 (already rotated) -> reuse detected.
    r = _refresh(client, t1["refresh_token"])
    assert r.status_code == 401
    assert "reuse" in r.json()["detail"]

    # The legitimate latest token (t3) is now dead as well.
    r = _refresh(client, t3["refresh_token"])
    assert r.status_code == 401

    with app.state.session_factory() as db:
        rows = db.scalars(select(RefreshToken)).all()
        assert len(rows) == 3
        assert all(row.revoked_at is not None for row in rows)
        assert len({row.family_id for row in rows}) == 1


def test_separate_logins_are_separate_families(api, client, app):
    device_a = api.signup("fam@example.com")
    device_b = api.login("fam@example.com")

    # Replaying a rotated token from device A must not log out device B.
    a2 = _refresh(client, device_a["refresh_token"]).json()
    assert _refresh(client, device_a["refresh_token"]).status_code == 401
    assert _refresh(client, a2["refresh_token"]).status_code == 401
    assert _refresh(client, device_b["refresh_token"]).status_code == 200

    with app.state.session_factory() as db:
        families = {row.family_id for row in db.scalars(select(RefreshToken))}
        assert len(families) == 2


def test_logout_revokes_refresh_token(api, client):
    tokens = api.signup("out@example.com")
    r = client.post("/v1/auth/logout", json={"refresh_token": tokens["refresh_token"]})
    assert r.status_code == 200
    assert _refresh(client, tokens["refresh_token"]).status_code == 401


def test_logout_all_revokes_every_session(api, client):
    t1 = api.signup("all@example.com")
    t2 = api.login("all@example.com")
    r = client.post("/v1/auth/logout-all", headers=api.auth(t1))
    assert r.status_code == 200
    assert "2" in r.json()["message"]
    assert _refresh(client, t1["refresh_token"]).status_code == 401
    assert _refresh(client, t2["refresh_token"]).status_code == 401


def test_unknown_refresh_token_rejected(client):
    assert _refresh(client, "definitely-not-a-token").status_code == 401


def test_expired_refresh_token_rejected(api, client, app):
    tokens = api.signup("stale@example.com")
    from datetime import datetime, timedelta, timezone

    with app.state.session_factory() as db:
        row = db.scalars(select(RefreshToken)).one()
        row.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    r = _refresh(client, tokens["refresh_token"])
    assert r.status_code == 401
    assert "expired" in r.json()["detail"]
