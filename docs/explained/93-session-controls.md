# 93. Browser session controls and workspace network policy

A browser left signed in on a shared or lost computer is an open door. So is a workspace reachable
from any café's Wi-Fi when the organisation only ever uses it from its offices or VPN.

## Idle timeout

A browser session now ends after `ARGUS_SESSION_IDLE_MINUTES` (default 60) without use, as well as
after its lifetime (`ARGUS_SESSION_TTL_HOURS`). The ended session is deleted, not merely refused;
the browser shows the sign-in page. `0` turns the idle limit off.

## Your sessions

Settings → **Your sessions** (for people who sign in with single sign-on) lists every browser signed
in as you: browser, address, when it was last active and when it signed in. You can sign out one,
or **sign out everywhere else**. Session ids are a prefix of the cookie's SHA-256: they identify a
session without revealing it.

* `GET /api/auth/sessions`, `DELETE /api/auth/sessions/{id}`, `POST /api/auth/sessions/end-others`;
* a platform administrator ends every session of a person with `POST /api/users/{id}/sign-out`
  (disabling the user, as before, also does).

## Network access per workspace

Settings → **Network access** (or `PUT /api/access-policy`, admin): the addresses or CIDRs a workspace
may be used from. It applies to everyone acting in the workspace, browser sessions and API keys alike,
on top of any per-key networks (Phase 89).

* A request from elsewhere gets `404`, as if the workspace did not exist. It is audited
  (`auth.forbidden` with the address) and counted (`argus_auth_failures_total{reason="workspace_network"}`).
* A policy that would shut out the administrator saving it is refused.
* Platform administrators are exempt, so a wrong policy can always be fixed.
* Changes reach every replica within 30 seconds.

Behind a reverse proxy, run uvicorn with `--proxy-headers` so Argus sees the real client address.

Python client: `access_policy()`, `set_access_policy()`, `sign_user_out()`.
