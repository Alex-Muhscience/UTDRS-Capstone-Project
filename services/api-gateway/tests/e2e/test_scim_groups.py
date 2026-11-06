"""SCIM groups: the identity provider manages membership; administrators decide what each group means."""
import os
import uuid

import pytest

from tests.e2e.test_scim import PATCH, SCIM, client, org, organisation, person  # noqa: F401  (fixtures)

pytestmark = pytest.mark.skipif(
    not os.environ.get("UTDRS_RUN_DB_TESTS"), reason="MONGODB_URI not set"
)

API = "/api/v1"
GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"


def provision(client, idp):
    return client.post(f"{SCIM}/Users", json=person(), headers=idp).json()


def role_of(client, admin, user_id):
    return client.get(f"{API}/users/{user_id}", headers=admin).json()


def patch(client, idp, group_id, *operations):
    return client.patch(f"{SCIM}/Groups/{group_id}", json={"schemas": [PATCH], "Operations": list(operations)}, headers=idp)


def map_group(client, admin, group_id, role, custom_role_id=None):
    return client.put(f"{API}/tenants/current/scim/groups/{group_id}/role", json={"role": role, "custom_role_id": custom_role_id}, headers=admin)


def test_identity_providers_create_find_and_change_groups(client, org):
    admin, idp = org
    ana, ben = provision(client, idp), provision(client, idp)
    created = client.post(f"{SCIM}/Groups", json={"schemas": [GROUP], "displayName": "SOC analysts", "externalId": "g-1",
                                                   "members": [{"value": ana["id"]}, {"value": "665f1c2ab1e2c3d4e5f6ffff"}]}, headers=idp)
    assert created.status_code == 201, created.text
    group = created.json()
    assert [m["value"] for m in group["members"]] == [ana["id"]]  # people not provisioned (yet) are left out
    assert created.headers["Location"].endswith(f"/Groups/{group['id']}")
    assert client.post(f"{SCIM}/Groups", json={"schemas": [GROUP], "displayName": "SOC analysts"}, headers=idp).status_code == 409

    found = client.get(f"{SCIM}/Groups", params={"filter": 'displayName eq "SOC analysts"'}, headers=idp).json()
    assert found["totalResults"] == 1 and found["Resources"][0]["id"] == group["id"]
    assert "members" not in client.get(f"{SCIM}/Groups", params={"excludedAttributes": "members"}, headers=idp).json()["Resources"][0]

    # Entra ID's and Okta's ways of changing membership.
    assert patch(client, idp, group["id"], {"op": "Add", "path": "members", "value": [{"value": ben["id"]}]}).status_code == 200
    assert patch(client, idp, group["id"], {"op": "Remove", "path": f'members[value eq "{ana["id"]}"]'}).json()["members"][0]["value"] == ben["id"]
    renamed = patch(client, idp, group["id"], {"op": "replace", "value": {"displayName": "Security analysts"}}).json()
    assert renamed["displayName"] == "Security analysts"
    assert patch(client, idp, group["id"], {"op": "replace", "path": "members", "value": []}).json()["members"] == []
    assert patch(client, idp, group["id"], {"op": "copy", "path": "x"}).status_code == 400
    assert client.delete(f"{SCIM}/Groups/{group['id']}", headers=idp).status_code == 204
    assert client.get(f"{SCIM}/Groups/{group['id']}", headers=idp).status_code == 404


def test_groups_give_their_members_roles(client, org):
    admin, idp = org
    ana = provision(client, idp)
    assert role_of(client, admin, ana["id"])["role"] == "analyst"  # as SCIM creates people
    readers = client.post(f"{SCIM}/Groups", json={"schemas": [GROUP], "displayName": "UTDRS readers", "members": [{"value": ana["id"]}]}, headers=idp).json()
    leads = client.post(f"{SCIM}/Groups", json={"schemas": [GROUP], "displayName": "UTDRS leads"}, headers=idp).json()

    # A group means nothing until an administrator says so.
    assert role_of(client, admin, ana["id"])["role"] == "analyst"
    groups = map_group(client, admin, readers["id"], "viewer").json()
    assert {g["display_name"]: g["role"] for g in groups} == {"UTDRS leads": None, "UTDRS readers": "viewer"}
    assert role_of(client, admin, ana["id"])["role"] == "viewer"

    # The most powerful of their groups wins.
    map_group(client, admin, leads["id"], "admin")
    patch(client, idp, leads["id"], {"op": "add", "path": "members", "value": [{"value": ana["id"]}]})
    assert role_of(client, admin, ana["id"])["role"] == "admin"
    patch(client, idp, leads["id"], {"op": "remove", "path": "members", "value": [{"value": ana["id"]}]})
    assert role_of(client, admin, ana["id"])["role"] == "viewer"

    # Out of every group with a role: read-only.
    patch(client, idp, readers["id"], {"op": "remove", "path": f'members[value eq "{ana["id"]}"]'})
    assert role_of(client, admin, ana["id"])["role"] == "viewer"
    log = client.get(f"{API}/audit-log/", params={"action": "scim"}, headers=admin).json()
    assert {"scim.role_changed", "scim.group_role_set", "scim.group_members_changed"} <= {e["action"] for e in log}


def test_custom_roles_from_groups_and_roles_set_by_hand(client, org):
    admin, idp = org
    ana, ben = provision(client, idp), provision(client, idp)
    triage = client.post(f"{API}/roles", json={"name": "Triage", "permissions": ["alerts:write"]}, headers=admin).json()
    group = client.post(f"{SCIM}/Groups", json={"schemas": [GROUP], "displayName": "Triage team", "members": [{"value": ana["id"]}]}, headers=idp).json()
    assert map_group(client, admin, group["id"], "custom").status_code == 422  # which custom role?
    map_group(client, admin, group["id"], "custom", triage["id"])
    assert (role_of(client, admin, ana["id"])["role"], role_of(client, admin, ana["id"])["custom_role_id"]) == ("custom", triage["id"])
    # The custom role cannot be deleted while a group gives it, even with nobody in the group.
    patch(client, idp, group["id"], {"op": "remove", "path": f'members[value eq "{ana["id"]}"]'})
    assert role_of(client, admin, ana["id"])["role"] == "viewer"
    refused = client.delete(f"{API}/roles/{triage['id']}", headers=admin)
    assert refused.status_code == 409 and "SCIM group" in refused.json()["detail"]

    # Someone whose role was set by hand keeps it outside groups with roles.
    client.patch(f"{API}/users/{ben['id']}", json={"role": "viewer"}, headers=admin)
    patch(client, idp, group["id"], {"op": "add", "path": "members", "value": [{"value": ben["id"]}]})
    assert role_of(client, admin, ben["id"])["role"] == "custom"  # a group with a role still decides
    patch(client, idp, group["id"], {"op": "remove", "path": "members", "value": [{"value": ben["id"]}]})
    assert role_of(client, admin, ben["id"])["role"] == "viewer"


def test_groups_never_demote_the_last_administrator(client, monkeypatch):
    admin, idp = organisation(client, monkeypatch)
    me = client.get(f"{API}/auth/me", headers=admin).json()
    readers = client.post(f"{SCIM}/Groups", json={"schemas": [GROUP], "displayName": "Readers", "members": [{"value": me["id"]}]}, headers=idp).json()
    map_group(client, admin, readers["id"], "viewer")
    assert client.get(f"{API}/auth/me", headers=admin).json()["role"] == "admin"
    log = client.get(f"{API}/audit-log/", params={"action": "scim"}, headers=admin).json()
    assert any(e["action"] == "scim.role_change_skipped" for e in log)


def test_only_administrators_say_what_groups_mean(client, org):
    admin, idp = org
    group = client.post(f"{SCIM}/Groups", json={"schemas": [GROUP], "displayName": f"G {uuid.uuid4().hex[:4]}"}, headers=idp).json()
    name = f"an_{uuid.uuid4().hex[:6]}"
    created = client.post(f"{API}/users/", json={"username": name, "email": f"{name}@example.com", "role": "analyst"}, headers=admin).json()
    analyst = {"Authorization": f"Bearer {client.post(f'{API}/auth/login', data={'username': name, 'password': created['temporary_password']}).json()['access_token']}"}
    assert map_group(client, analyst, group["id"], "admin").status_code == 403
    assert client.get(f"{API}/tenants/current/scim/groups", headers=analyst).status_code == 403
    assert map_group(client, admin, "665f1c2ab1e2c3d4e5f6ffff", "admin").status_code == 404
