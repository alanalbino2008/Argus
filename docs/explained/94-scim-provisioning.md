# 94. SCIM provisioning from the identity provider

Joining and leaving should be handled in one place. When someone leaves the organisation, their
account is disabled in Okta or Entra ID, and every application should follow at once, not when
someone remembers. SCIM 2.0 is how identity providers tell applications.

## Switching it on

1. Set `ARGUS_SCIM_TOKEN` to a long random value on the server.
2. In the identity provider, add Argus as a SCIM 2.0 application: base URL
   `https://<argus>/scim/v2`, authentication "Bearer token", the token from step 1. Settings →
   **Provisioning (SCIM)** shows the exact URL.
3. Map the identity provider's groups to workspace roles in the same card (or
   `PUT /api/scim/group-roles` with `{"group", "workspace_id", "role"}`).

Without the token, every `/scim/v2` path answers 404.

## What the identity provider can do

| Action | Effect in Argus |
| --- | --- |
| Create a user | A provisioned user. Their first single sign-on with the same email **is** that user (no duplicate). Someone who already signed in before SCIM is adopted, not duplicated. |
| Deactivate (`active: false`) or delete a user | The user is disabled and **signed out of every browser at once**. Their history stays, for the audit trail. |
| Reactivate | Access returns, from their groups. |
| Create or change a group, add or remove members | Members of a mapped group get that role in that workspace; leaving the group removes it. With several groups, the highest role wins. |

Only provisioned users who never signed in are linked by email at first sign-in, so an existing
account cannot be taken over through an email address.

SCIM only ever changes **memberships it created**. A membership added or changed by an administrator
belongs to that administrator, and SCIM leaves it alone.

Supported: `Users` and `Groups` (list with `filter` `attribute eq "value"`, get, create, replace,
patch, delete), `ServiceProviderConfig`, `ResourceTypes`, `Schemas`. The patch forms used by Okta
(member filters such as `members[value eq "…"]`) and Entra ID (capitalised operations, `"True"`/`"False"`
strings) both work. Errors use SCIM's error format.

Every change is audited (`scim.user_create`, `scim.user_update`, `scim.user_deactivate`,
`scim.group_*`, `scim.membership`, `scim.group_role`), as are refused tokens (`scim.auth_failed`).

Python client: `scim_group_roles()`, `map_scim_group()`.
