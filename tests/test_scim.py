"""Phase 94: SCIM 2.0 provisioning, as Okta and Microsoft Entra ID drive it."""

from __future__ import annotations

from datetime import timedelta

import pytest

from tests.test_workspaces import as_user

TOKEN = "scim-token-0123456789abcdefghijkl"
SCIM = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/scim+json"}
WS = "ws_default"


@pytest.fixture
def c(make_client):
    return make_client(scim_token=TOKEN)


def _okta_user(email, external="00u1", active=True):
    return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": email, "externalId": external,
            "name": {"givenName": "Dana", "familyName": "Lee"}, "emails": [{"primary": True, "value": email, "type": "work"}],
            "active": active}  # fmt: skip


def _members(c, workspace=WS):
    return {m["user_id"]: m["role"] for m in c.get(f"/api/workspaces/{workspace}/members").json()}


def _session(c, user_id):
    async def make():
        return await c.app.state.users.create_session(user_id, timedelta(hours=1), None, None)

    return {"token": c.portal.call(make)}


def test_scim_is_off_without_a_token(client):
    assert client.get("/scim/v2/Users", headers=SCIM).status_code == 404
    assert client.get("/api/scim/group-roles").json()["enabled"] is False


def test_the_token_is_checked(c):
    assert c.get("/scim/v2/Users", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/scim/v2/Users").status_code == 401
    config = c.get("/scim/v2/ServiceProviderConfig", headers=SCIM)
    assert config.status_code == 200 and config.headers["content-type"].startswith("application/scim+json")
    assert config.json()["patch"]["supported"] is True
    assert "scim.auth_failed" in {e["action"] for e in c.get("/api/audit?limit=100").json()}


def test_users_are_provisioned_found_and_unique(c):
    created = c.post("/scim/v2/Users", json=_okta_user("dana@acme.example"), headers=SCIM)
    assert created.status_code == 201, created.text
    user = created.json()
    assert user["userName"] == "dana@acme.example" and user["active"] and user["displayName"] == "Dana Lee"
    found = c.get('/scim/v2/Users?filter=userName eq "Dana@Acme.example"', headers=SCIM).json()
    assert found["totalResults"] == 1 and found["Resources"][0]["id"] == user["id"]
    assert c.get('/scim/v2/Users?filter=externalId eq "00u1"', headers=SCIM).json()["totalResults"] == 1
    assert c.get('/scim/v2/Users?filter=title co "x"', headers=SCIM).json()["scimType"] == "invalidFilter"
    again = c.post("/scim/v2/Users", json=_okta_user("dana@acme.example"), headers=SCIM)
    assert again.status_code == 409 and again.json()["scimType"] == "uniqueness"
    assert c.get("/scim/v2/Users/usr_nope", headers=SCIM).json()["status"] == "404"

    # Her first single sign-on is the provisioned user, not a second one.
    async def login():
        return await c.app.state.users.upsert_from_login(issuer="https://idp.acme.example", subject="sso-dana",
                                                         email="dana@acme.example", name="Dana Lee", role="viewer",
                                                         role_from_idp=False)  # fmt: skip

    assert c.portal.call(login)["id"] == user["id"]
    assert c.get("/scim/v2/Users", headers=SCIM).json()["totalResults"] == 1


def test_an_existing_sso_user_is_adopted_not_duplicated(c):
    async def login():
        return await c.app.state.users.upsert_from_login(issuer="https://idp", subject="s1", email="eve@acme.example",
                                                         name="Eve", role="viewer", role_from_idp=False)  # fmt: skip

    existing = c.portal.call(login)
    adopted = c.post("/scim/v2/Users", json=_okta_user("eve@acme.example", external="00u9"), headers=SCIM).json()
    assert adopted["id"] == existing["id"]


def test_groups_give_workspace_roles_and_leaving_removes_them(c):
    dana = c.post("/scim/v2/Users", json=_okta_user("dana@acme.example"), headers=SCIM).json()
    sam = c.post("/scim/v2/Users", json=_okta_user("sam@acme.example", external="00u2"), headers=SCIM).json()
    group = c.post("/scim/v2/Groups", headers=SCIM, json={
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "Argus Analysts",
        "members": [{"value": dana["id"]}]}).json()  # fmt: skip
    assert _members(c).get(dana["id"]) is None  # no mapping yet: no access

    mapped = c.put("/api/scim/group-roles", json={"group": "argus analysts", "workspace_id": WS, "role": "analyst"})
    assert mapped.status_code == 200 and mapped.json()["enabled"] and mapped.json()["mappings"][0]["role"] == "analyst"
    assert _members(c)[dana["id"]] == "analyst"

    # Okta adds a member; a second group gives a higher role; the highest wins.
    patch = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
             "Operations": [{"op": "add", "path": "members", "value": [{"value": sam["id"]}]}]}  # fmt: skip
    assert c.patch(f"/scim/v2/Groups/{group['id']}", json=patch, headers=SCIM).status_code == 200
    admins = c.post(
        "/scim/v2/Groups", headers=SCIM, json={"displayName": "Argus Admins", "members": [{"value": sam["id"]}]}
    ).json()
    c.put("/api/scim/group-roles", json={"group": "Argus Admins", "workspace_id": WS, "role": "admin"})
    assert _members(c)[sam["id"]] == "admin" and _members(c)[dana["id"]] == "analyst"

    # A membership added by hand is never touched by SCIM.
    async def manual():
        await c.app.state.workspaces.set_member(WS, dana["id"], "admin", "bootstrap-admin")

    c.portal.call(manual)
    remove = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
              "Operations": [{"op": "remove", "path": f'members[value eq "{dana["id"]}"]'}]}  # fmt: skip
    c.patch(f"/scim/v2/Groups/{group['id']}", json=remove, headers=SCIM)
    assert _members(c)[dana["id"]] == "admin"  # kept: an administrator added it

    # Sam leaves the admins group: back to analyst; the group is deleted: no access.
    c.patch(
        f"/scim/v2/Groups/{admins['id']}",
        headers=SCIM,
        json={"Operations": [{"op": "replace", "path": "members", "value": []}]},
    )
    assert _members(c)[sam["id"]] == "analyst"
    assert c.delete(f"/scim/v2/Groups/{group['id']}", headers=SCIM).status_code == 204
    assert sam["id"] not in _members(c)
    actions = {e["action"] for e in c.get("/api/audit?limit=200").json()}
    assert {
        "scim.user_create",
        "scim.group_create",
        "scim.group_update",
        "scim.group_delete",
        "scim.group_role",
    } <= actions


def test_deactivation_signs_out_everywhere_at_once(c):
    dana = c.post("/scim/v2/Users", json=_okta_user("dana@acme.example"), headers=SCIM).json()
    c.post("/scim/v2/Groups", headers=SCIM, json={"displayName": "Argus Analysts", "members": [{"value": dana["id"]}]})
    c.put("/api/scim/group-roles", json={"group": "Argus Analysts", "workspace_id": WS, "role": "analyst"})
    browser = _session(c, dana["id"])
    assert c.get("/api/cases", headers=as_user(browser)).status_code == 200

    # Microsoft Entra ID deactivates with a capitalised op and a string boolean.
    entra = {"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
             "Operations": [{"op": "Replace", "path": "active", "value": "False"}]}  # fmt: skip
    patched = c.patch(f"/scim/v2/Users/{dana['id']}", json=entra, headers=SCIM)
    assert patched.status_code == 200 and patched.json()["active"] is False
    assert c.get("/api/cases", headers=as_user(browser)).status_code == 401  # signed out at once
    assert dana["id"] not in _members(c)  # and its SCIM memberships are gone
    deactivated = next(e for e in c.get("/api/audit?limit=200").json() if e["action"] == "scim.user_update")
    assert deactivated["details"]["sessions_ended"] == 1

    # Reactivated: access comes back from the groups. DELETE deactivates again.
    c.patch(
        f"/scim/v2/Users/{dana['id']}",
        headers=SCIM,
        json={"Operations": [{"op": "replace", "value": {"active": True}}]},
    )
    assert _members(c)[dana["id"]] == "analyst"
    assert c.delete(f"/scim/v2/Users/{dana['id']}", headers=SCIM).status_code == 204
    assert c.get(f"/scim/v2/Users/{dana['id']}", headers=SCIM).json()["active"] is False
