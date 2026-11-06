"""Reading the audit log: who may, what they see, how it pages."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from saas_auth import audit
from saas_auth.audit import Action, Actor
from saas_auth.models import AuditEvent
from saas_auth.rbac import has_permission


def url(org_id: str) -> str:
    return f"/v1/orgs/{org_id}/audit-events"


@pytest.fixture
def team(api):
    owner = api.signup("owner@acme.com")
    org = api.create_org(owner, "Acme Ltd")
    admin = api.invite_and_accept(owner, org["id"], "admin@acme.com", "admin")
    member = api.invite_and_accept(owner, org["id"], "member@acme.com", "member")
    viewer = api.invite_and_accept(owner, org["id"], "viewer@acme.com", "viewer")
    return dict(org=org, owner=owner, admin=admin, member=member, viewer=viewer)


def seed(app, org_id: str, count: int, created_at: datetime | None = None) -> None:
    """Insert events directly so tests control their number and timestamps."""
    with app.state.session_factory() as db:
        for _ in range(count):
            event = audit.record_for_org(
                db, org_id, Actor.system(), Action.ORG_DELETED, ("org", org_id)
            )
            if created_at is not None:
                event.created_at = created_at
        db.commit()


def test_only_owner_and_admin_hold_audit_read():
    assert has_permission("owner", "audit:read")
    assert has_permission("admin", "audit:read")
    assert not has_permission("member", "audit:read")
    assert not has_permission("viewer", "audit:read")


@pytest.mark.parametrize(("role", "status"), [("owner", 200), ("admin", 200)])
def test_owner_and_admin_can_list(api, client, team, role, status):
    r = client.get(url(team["org"]["id"]), headers=api.auth(team[role]))
    assert r.status_code == status
    assert {e["action"] for e in r.json()["items"]} >= {"invitation.created"}


@pytest.mark.parametrize("role", ["member", "viewer"])
def test_lower_roles_are_refused(api, client, team, role):
    r = client.get(url(team["org"]["id"]), headers=api.auth(team[role]))
    assert r.status_code == 403
    assert r.json()["detail"]["missing"] == ["audit:read"]


def test_anonymous_is_refused(client, team):
    assert client.get(url(team["org"]["id"])).status_code == 401


def test_api_key_needs_the_audit_scope(api, client, team):
    org_id = team["org"]["id"]

    def key_with(*scopes: str) -> dict:
        r = client.post(
            f"/v1/orgs/{org_id}/api-keys",
            json={"name": "siem", "scopes": list(scopes)},
            headers=api.auth(team["owner"]),
        )
        assert r.status_code == 201, r.text
        return {"X-API-Key": r.json()["key"]}

    assert client.get(url(org_id), headers=key_with("audit:read")).status_code == 200
    assert client.get(url(org_id), headers=key_with("org:read")).status_code == 403


def test_member_cannot_mint_a_key_with_the_audit_scope(api, client, team):
    r = client.post(
        f"/v1/orgs/{team['org']['id']}/api-keys",
        json={"name": "sneaky", "scopes": ["audit:read"]},
        headers=api.auth(team["member"]),
    )
    assert r.status_code == 403


def test_other_organizations_get_404_and_never_see_foreign_rows(api, client, team):
    outsider = api.signup("outsider@globex.com")
    globex = api.create_org(outsider, "Globex")
    org_id = team["org"]["id"]

    assert client.get(url(org_id), headers=api.auth(outsider)).status_code == 404
    assert client.get(url(globex["id"]), headers=api.auth(outsider)).json()["items"] == []


def test_key_from_another_organization_gets_404(api, client, team):
    outsider = api.signup("outsider@globex.com")
    globex = api.create_org(outsider, "Globex")
    r = client.post(
        f"/v1/orgs/{globex['id']}/api-keys",
        json={"name": "siem", "scopes": ["audit:read"]},
        headers=api.auth(outsider),
    )
    r = client.get(url(team["org"]["id"]), headers={"X-API-Key": r.json()["key"]})
    assert r.status_code == 404


def test_cursor_from_another_organization_shows_nothing_foreign(app, api, client, team):
    outsider = api.signup("outsider@globex.com")
    globex = api.create_org(outsider, "Globex")
    seed(app, team["org"]["id"], 3)
    seed(app, globex["id"], 1)

    page = client.get(
        url(team["org"]["id"]), params={"limit": 1}, headers=api.auth(team["owner"])
    ).json()
    r = client.get(
        url(globex["id"]), params={"cursor": page["next_cursor"]}, headers=api.auth(outsider)
    )
    assert r.status_code == 200
    assert {e["org_id"] for e in r.json()["items"]} <= {globex["id"]}


def test_unscoped_events_are_not_visible_to_any_organization(app, api, client, team):
    with app.state.session_factory() as db:
        db.add(
            AuditEvent(
                org_id=None,
                actor_kind="system",
                action="user.locked",
                target_type="user",
                target_id="someone",
            )
        )
        db.commit()
    r = client.get(
        url(team["org"]["id"]),
        params={"action": "user.locked"},
        headers=api.auth(team["owner"]),
    )
    assert r.json()["items"] == []


def test_response_shape_and_newest_first(api, client, team):
    r = client.get(url(team["org"]["id"]), headers=api.auth(team["owner"]))
    items = r.json()["items"]
    assert set(items[0]) == {
        "id",
        "org_id",
        "actor_kind",
        "actor_id",
        "action",
        "target_type",
        "target_id",
        "metadata",
        "ip",
        "created_at",
    }
    assert items == sorted(items, key=lambda e: (e["created_at"], e["id"]), reverse=True)


def test_cursor_walks_every_event_exactly_once_across_identical_timestamps(app, api, client, team):
    org_id = team["org"]["id"]
    seed(app, org_id, 7, created_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    expected = len(client.get(url(org_id), headers=api.auth(team["owner"])).json()["items"])

    seen, cursor = [], None
    while True:
        params = {"limit": 2} | ({"cursor": cursor} if cursor else {})
        body = client.get(url(org_id), params=params, headers=api.auth(team["owner"])).json()
        assert len(body["items"]) <= 2
        seen += [e["id"] for e in body["items"]]
        cursor = body["next_cursor"]
        if cursor is None:
            break

    assert len(seen) == len(set(seen)) == expected


def test_last_page_has_no_cursor(app, api, client, team):
    r = client.get(url(team["org"]["id"]), params={"limit": 200}, headers=api.auth(team["owner"]))
    assert r.json()["next_cursor"] is None


@pytest.mark.parametrize("limit", [0, 201])
def test_limit_is_bounded(api, client, team, limit):
    r = client.get(url(team["org"]["id"]), params={"limit": limit}, headers=api.auth(team["owner"]))
    assert r.status_code == 422


@pytest.mark.parametrize(
    "cursor",
    [
        "garbage",
        "%%%",
        "bm90LWEtY3Vyc29y",  # valid base64, wrong content
        "MjAyNi0wMS0wMVQwMDowMDowMHxub3QtYS11dWlk",  # valid date, id is not a uuid
        "MjAyNi0wMS0wMVQwMDowMDowMHwA",  # NUL byte for an id
    ],
)
def test_bad_cursor_is_a_client_error(api, client, team, cursor):
    r = client.get(
        url(team["org"]["id"]), params={"cursor": cursor}, headers=api.auth(team["owner"])
    )
    assert r.status_code == 400


def test_filter_by_action(api, client, team):
    r = client.get(
        url(team["org"]["id"]),
        params={"action": "invitation.accepted"},
        headers=api.auth(team["owner"]),
    )
    items = r.json()["items"]
    assert len(items) == 3
    assert {e["action"] for e in items} == {"invitation.accepted"}


def test_unknown_action_is_rejected(api, client, team):
    r = client.get(
        url(team["org"]["id"]), params={"action": "nope"}, headers=api.auth(team["owner"])
    )
    assert r.status_code == 422


def test_filter_by_actor(api, client, team):
    me = client.get("/v1/auth/me", headers=api.auth(team["viewer"])).json()["id"]
    r = client.get(url(team["org"]["id"]), params={"actor_id": me}, headers=api.auth(team["owner"]))
    assert [e["action"] for e in r.json()["items"]] == ["invitation.accepted"]


@pytest.mark.parametrize("actor_id", ["x", "a\x00" * 12])
def test_malformed_actor_is_rejected(api, client, team, actor_id):
    r = client.get(
        url(team["org"]["id"]), params={"actor_id": actor_id}, headers=api.auth(team["owner"])
    )
    assert r.status_code == 422


def test_date_range_includes_since_and_excludes_until(app, api, client, team):
    org_id = team["org"]["id"]
    moment = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for offset in (0, 1, 2):
        seed(app, org_id, 1, created_at=moment + timedelta(days=offset))

    def count(**params) -> int:
        r = client.get(url(org_id), params=params, headers=api.auth(team["owner"]))
        assert r.status_code == 200, r.text
        return len(r.json()["items"])

    start, stop = moment.isoformat(), (moment + timedelta(days=2)).isoformat()
    assert count(since=start, until=stop) == 2
    assert count(until=stop) == 2
    assert count(since=start, action="org.deleted") == 3
    # A date without an offset means UTC, and mixing the two styles is not an error.
    assert count(since="2026-01-01T00:00:00", until=stop) == 2


def test_inverted_or_unrepresentable_range_is_rejected(api, client, team):
    org_id = team["org"]["id"]
    headers = api.auth(team["owner"])
    r = client.get(
        url(org_id),
        params={"since": "2026-02-01T00:00:00", "until": "2026-01-01T00:00:00+00:00"},
        headers=headers,
    )
    assert r.status_code == 422
    r = client.get(url(org_id), params={"since": "0001-01-01T00:00:00+14:00"}, headers=headers)
    assert r.status_code == 422


@pytest.mark.parametrize(
    ("method", "path"),
    [("post", ""), ("put", ""), ("patch", ""), ("delete", ""), ("delete", "/some-id")],
)
def test_no_route_can_write_or_remove_events(api, client, team, method, path):
    r = client.request(
        method, url(team["org"]["id"]) + path, headers=api.auth(team["owner"]), json={}
    )
    assert r.status_code in (404, 405)
