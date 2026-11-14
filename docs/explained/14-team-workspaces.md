# 14 — Team Workspaces (Plain-English Guide)

> Purpose: explain how several teams share one Argus deployment without seeing each other's
> work, and how the isolation is enforced. It's useful for "how do you build multi-tenancy?" and
> "how do you prevent IDOR / broken object-level authorization?" questions.

## 1. What a workspace is

A **workspace** is a team's private space: its investigations, monitors, alerts, API keys and
audit entries. The red team, the threat-intel team and a client engagement can each have one on
the same server. Nobody in one workspace can see, or even confirm, anything in another.

Every installation starts with a **Default** workspace. Upgrading moves all existing data, users
and non-admin API keys into it, so nothing changes until a second workspace is created.

## 2. Who can do what

| Who | Can |
|---|---|
| **Viewer** in a workspace | Read its investigations, graphs, reports and alerts |
| **Analyst** in a workspace | Also run scans, create monitors, acknowledge alerts |
| **Admin** of a workspace | Also add and remove members, change their roles, manage the workspace's API keys and read its audit log |
| **Platform admin** | Create and delete workspaces, manage users, open any workspace, verify the whole audit chain |

A person's role is **per workspace**: you can be an admin of *Red Team* and a viewer in *Default*.
A platform admin is an administrator user, or an admin API key that isn't bound to a workspace.

## 3. How isolation is enforced

The most common real-world API flaw is **broken object-level authorization (BOLA/IDOR)**. It's
the top entry in the OWASP API Top 10: an API checks *that* you're logged in, but not *whether
this object is yours*. Argus defends against it in layers:

1. **Every request resolves one workspace** (`argus/api/deps.py: resolve_workspace`). The browser
   sends the `X-Argus-Workspace` header. Argus checks membership, and the result becomes a
   `WorkspaceContext` that endpoints receive instead of a bare identity.
2. **Repositories demand a workspace.** Functions that list or search data take `workspace_id` as
   a *required keyword argument*, so the type checker flags any call that forgets it.
3. **Single-object lookups compare the owner.** An investigation, monitor or alert from another
   workspace is answered with **404 Not Found**, never 403. A 403 would confirm that the ID exists.
4. **Bound API keys** belong to exactly one workspace. Asking for another workspace returns 404,
   whatever the header says.
5. **Live streams too.** WebSocket tickets are bound to the workspace they were issued for, and
   the socket closes if the investigation belongs elsewhere.
6. **Background work stays inside.** A scheduled monitor's scans, drift alerts and audit entries
   inherit the monitor's workspace.
7. **A test sweeps every route** (`tests/test_workspaces.py`). It creates data in one workspace,
   calls every ID-taking endpoint from another, and requires 404 on all of them. A new endpoint
   that forgets the check fails CI.

## 4. Single sign-on and workspaces

* `sso.defaultWorkspace` (default `default`): new SSO users join it on their first sign-in. Set it
  to `""` if workspace admins should add people by hand.
* `sso.workspaceGroups`: maps identity-provider groups to workspaces, e.g.
  `{red-team: red-team}`. Argus mirrors them at every sign-in. Someone removed from the group in
  the identity provider leaves the workspace at their next sign-in.
* Workspace admins can add anyone who has signed in once, by email, in *Settings → Workspace*.

## 5. The audit log

Audit entries record their workspace, and the workspace ID is part of each entry's hash, so it
can't be quietly edited. Entries written before the upgrade still verify, because the ID is only
hashed when present. Workspace admins see their own workspace's entries. Platform admins see
everything and run the chain verification.

## 6. Interview talking points

* "Multi-tenancy is an authorization problem at the **object** level, not the endpoint level."
* "404 instead of 403 for foreign objects, so the API isn't an existence oracle."
* "I made the unsafe call impossible to write by accident: required keyword arguments and a
  route-sweep test that fails when someone adds an unscoped endpoint."
* "Roles are per workspace. Platform administration is a separate privilege, so a workspace admin
  can't escalate to the whole server."
