from __future__ import annotations

import pytest

from saas_auth.rbac import ROLE_PERMISSIONS, Role, has_permission, permissions_for, require


def test_permission_map_is_strictly_nested():
    viewer, member = ROLE_PERMISSIONS[Role.VIEWER], ROLE_PERMISSIONS[Role.MEMBER]
    admin, owner = ROLE_PERMISSIONS[Role.ADMIN], ROLE_PERMISSIONS[Role.OWNER]
    assert viewer < member < admin < owner
    assert has_permission("viewer", "projects:read")
    assert not has_permission("viewer", "projects:create")
    assert has_permission("owner", "org:delete")


def test_permissions_for_unknown_role_raises():
    with pytest.raises(ValueError):
        permissions_for("superuser")


def test_require_rejects_unknown_permission_at_import_time():
    with pytest.raises(ValueError):
        require("galaxy:destroy")


@pytest.fixture
def org_with_roles(api):
    owner = api.signup("owner@acme.com")
    org = api.create_org(owner, "Acme Ltd")
    admin = api.invite_and_accept(owner, org["id"], "admin@acme.com", "admin")
    member = api.invite_and_accept(owner, org["id"], "member@acme.com", "member")
    viewer = api.invite_and_accept(owner, org["id"], "viewer@acme.com", "viewer")
    return {"org": org, "owner": owner, "admin": admin, "member": member, "viewer": viewer}


def test_viewer_can_read_but_not_create_projects(api, client, org_with_roles):
    org, viewer = org_with_roles["org"], org_with_roles["viewer"]
    url = f"/v1/orgs/{org['id']}/projects"
    assert client.get(url, headers=api.auth(viewer)).status_code == 200
    r = client.post(url, json={"name": "Nope"}, headers=api.auth(viewer))
    assert r.status_code == 403
    assert r.json()["detail"]["missing"] == ["projects:create"]


def test_member_can_create_but_not_delete_projects(api, client, org_with_roles):
    org, member, admin = org_with_roles["org"], org_with_roles["member"], org_with_roles["admin"]
    url = f"/v1/orgs/{org['id']}/projects"
    r = client.post(url, json={"name": "Billing revamp"}, headers=api.auth(member))
    assert r.status_code == 201
    project_id = r.json()["id"]
    assert client.delete(f"{url}/{project_id}", headers=api.auth(member)).status_code == 403
    assert client.delete(f"{url}/{project_id}", headers=api.auth(admin)).status_code == 200


def test_member_cannot_invite(api, client, org_with_roles):
    org, member = org_with_roles["org"], org_with_roles["member"]
    r = client.post(
        f"/v1/orgs/{org['id']}/invitations",
        json={"email": "friend@acme.com", "role": "member"},
        headers=api.auth(member),
    )
    assert r.status_code == 403


def test_only_owner_can_delete_org(api, client, org_with_roles):
    org, admin, owner = org_with_roles["org"], org_with_roles["admin"], org_with_roles["owner"]
    assert client.delete(f"/v1/orgs/{org['id']}", headers=api.auth(admin)).status_code == 403
    assert client.delete(f"/v1/orgs/{org['id']}", headers=api.auth(owner)).status_code == 200
    assert client.get(f"/v1/orgs/{org['id']}", headers=api.auth(owner)).status_code == 404


def test_admin_can_change_roles_but_not_grant_ownership(api, client, org_with_roles):
    org, admin = org_with_roles["org"], org_with_roles["admin"]
    members = client.get(f"/v1/orgs/{org['id']}/members", headers=api.auth(admin)).json()
    by_email = {m["email"]: m for m in members}
    assert len(members) == 4

    viewer_id = by_email["viewer@acme.com"]["user_id"]
    r = client.patch(
        f"/v1/orgs/{org['id']}/members/{viewer_id}",
        json={"role": "member"},
        headers=api.auth(admin),
    )
    assert r.status_code == 200 and r.json()["role"] == "member"

    r = client.patch(
        f"/v1/orgs/{org['id']}/members/{viewer_id}",
        json={"role": "owner"},
        headers=api.auth(admin),
    )
    assert r.status_code == 403


def test_last_owner_cannot_be_demoted_or_removed(api, client, org_with_roles):
    org, owner = org_with_roles["org"], org_with_roles["owner"]
    members = client.get(f"/v1/orgs/{org['id']}/members", headers=api.auth(owner)).json()
    owner_id = next(m["user_id"] for m in members if m["role"] == "owner")

    r = client.patch(
        f"/v1/orgs/{org['id']}/members/{owner_id}",
        json={"role": "admin"},
        headers=api.auth(owner),
    )
    assert r.status_code == 409
    r = client.delete(f"/v1/orgs/{org['id']}/members/{owner_id}", headers=api.auth(owner))
    assert r.status_code == 409
    r = client.post(f"/v1/orgs/{org['id']}/members/leave", headers=api.auth(owner))
    assert r.status_code == 409


def test_member_can_leave(api, client, org_with_roles):
    org, member = org_with_roles["org"], org_with_roles["member"]
    r = client.post(f"/v1/orgs/{org['id']}/members/leave", headers=api.auth(member))
    assert r.status_code == 200
    assert client.get(f"/v1/orgs/{org['id']}", headers=api.auth(member)).status_code == 404
