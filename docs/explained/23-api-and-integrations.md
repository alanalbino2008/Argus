# 23 — API & Integrations (Plain-English Guide)

> Purpose: explain how other software talks to Argus, and how Argus puts its findings into the
> tools a security team already lives in. It's useful for questions like:
> * "what makes an API good to build on?"
> * "how do you integrate with Jira or a SIEM?"
> * "what is idempotency and why does it matter?"
> * "how do you stop an integration becoming an SSRF hole?"

## 1. Why this matters

A security team doesn't want another screen to watch. Its work already happens in a few places:
* **tickets** (Jira, ServiceNow): where work is assigned and tracked;
* **the SIEM** (Splunk, Microsoft Sentinel): where every security signal is collected,
  correlated and turned into detections;
* **its own scripts and pipelines**.

A finding that never reaches those places tends to be ignored. Commercial attack-surface and
rating platforms sell exactly this as "integrations". Argus now has them, built on the delivery
machinery from Phase 15.

## 2. A documented public API

Everything the web app does already went through the REST API. Phase 23 makes it **documented and
predictable** for outside developers:

* **OpenAPI 3.1** at `/openapi.json`, browsable at `/docs`. FastAPI generates the operations, and a
  small post-processor (`argus/api/openapi.py`) adds what it can't infer from Argus's own security
  code:
  * **Security schemes**: an API key as `Authorization: Bearer` or `X-API-Key`, declared exactly on
    the operations that need it. The seven public ones, such as health checks and report
    verification, are marked public.
  * The **`X-Argus-Workspace` header**, on every workspace-scoped operation.
  * The **minimum role** of each operation (`x-argus-role`), worked out by walking the
    operation's FastAPI dependency tree. It is never written by hand, so it cannot drift from the
    code.
  * **Stable operation IDs** (`start_scan`, `list_suppliers`…), so client generators produce
    readable method names.
  * A **tag** for every operation, so the reference reads by area.
* **Rate limiting per API key**: 600 requests a minute by default. Every response says where you
  stand with the IETF draft `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset`
  headers. A `429` adds `Retry-After`, so a well-behaved client knows exactly how long to wait.
  Without a limit, one runaway script can starve everyone else.
* **One error shape**: `{"detail": "…"}`, written for a person to read.
* **An official Python client** (`clients/python`). It handles authentication and workspaces,
  waits out rate limits using `Retry-After`, turns errors into typed exceptions (`NotFound`,
  `PermissionDenied`…), can wait for a scan to finish, and verifies webhook signatures. Its tests
  run it against the real application, not against mocks of it.
* **`docs/API.md`**: a quickstart, conventions, webhooks and integration setup.

## 3. Integrations

The four new destinations reuse the notification pipeline: an alert is written to the **outbox**
in the same database transaction as the alert itself, then delivered with retries, backoff, a
delivery log and encrypted credentials.

| Integration | What happens | Authentication |
|---|---|---|
| **Jira** (Cloud or Data Center) | each alert opens **one issue** | email + API token, or a personal access token |
| **ServiceNow** | each alert opens **one incident**, impact/urgency from severity | integration user (basic auth) |
| **Splunk** | alerts, reports and tests become HEC events | HEC token |
| **Microsoft Sentinel** | the same, as rows in a custom Log Analytics table | Entra ID app, OAuth client credentials |

**Send test** checks the real connection. For Jira it checks that the project exists and has the
chosen issue type. For ServiceNow it checks that the user can read incidents. Neither creates a
ticket. The delivery log then shows what each delivery created: `SEC-12`, `INC0010001`.

## 4. The interesting problem: exactly one ticket

Network deliveries are **at-least-once**. Suppose Argus asks Jira to create an issue, Jira creates
it, and then the response is lost (a timeout, a proxy hiccup). Argus can't tell "never arrived"
from "arrived but the reply was lost", so it retries. A naive retry opens a **second ticket**. Over
months that is a trickle of duplicates that people learn to ignore.

The fix is **idempotency**: making a repeated operation have the same effect as doing it once.
Each alert carries a **correlation key**:
* in Jira, a label `argus-<alert id>`;
* in ServiceNow, the `correlation_id` field, which is designed for exactly this.

Before creating anything, Argus searches for the key. If a ticket already exists, the delivery
succeeds and points to it ("SEC-12 (already existed)"). The end-to-end test runs a fake Jira on
localhost that creates the issue and then answers `504`. It checks that the retry creates nothing
and reports the existing issue.

(SIEMs don't need this: every event carries its `id`, and searches deduplicate on it.)

## 5. Security: integrations hold credentials

Integrations store powerful secrets (a Jira token can read every ticket the account can).
Several decisions protect them:

* **Write-only credentials.** Tokens, passwords and client secrets are encrypted with AES-256-GCM
  (`SecretBox`, Phase 15), bound to the channel's row, and never returned by the API.
* **Everything needed to send is sealed together, URL included.** If the URL were stored in clear
  next to an encrypted token, someone able to edit the database could point the token at their
  own server. Because the URL is inside the authenticated encryption, any change to it is
  detected.
* **Changing the host means re-entering the credential.** Editing a channel can keep a saved
  token, which is convenient, but only while the host stays the same. Otherwise an admin who
  never saw the token could redirect it to a server they control and capture it.
* **Server-side request forgery (SSRF).** A destination makes the *server* send requests to an
  address a *user* typed, the textbook SSRF shape. Argus refuses private, loopback and link-local
  addresses. It re-checks after every DNS lookup, so a hostname that later re-points to an
  internal address is caught (DNS rebinding). It never follows redirects.
* **…with an operator-controlled exception.** Real SIEMs often live on internal networks. The
  operator, not a workspace user, can list exact host names in `ARGUS_INTEGRATION_ALLOWED_HOSTS`.
  Even then, **link-local and cloud-metadata addresses stay blocked** (`169.254.169.254`, AWS's
  IPv6 `fd00:ec2::254`, Alibaba's `100.100.100.200`). Stealing cloud credentials from the
  metadata service is the classic SSRF prize (the 2019 Capital One breach).
* **Untrusted text stays inert.** Alert text contains names found on the internet. In Jira it goes
  inside a `{noformat}` block, which Jira does not interpret, so a hostile domain name cannot add
  links or mention people. Any attempt to close the block early is defused.
* **Error messages tell you what's wrong without leaking.** When Jira says
  `priority: Field 'priority' cannot be set`, that exact field-level message is shown. Raw
  response bodies never are, so a destination can't be used to read pages from a server.

## 6. Sentinel in a little more detail

Microsoft's **Logs Ingestion API** is the current way to send custom data to Sentinel:
1. Argus signs in to Entra ID with the **OAuth 2.0 client-credentials** flow.
2. It caches the access token until five minutes before it expires.
3. It posts rows to a **data collection rule** (DCR) through a **data collection endpoint** (DCE).
4. If a token is rejected early (revoked), the cache is cleared and the retry signs in again.

The token authority and scope follow the endpoint's cloud, so Azure Government and Azure China
work too. Rows are flat columns (time, type, severity, target, headline, link) plus a `Details`
column holding the whole event, which keeps analytics rules simple. Sign-in failures quote only
the Entra error code (`AADSTS7000215`, an invalid client secret), not the trace text.

## 7. What a reviewer can check

* `tests/test_integrations.py`:
  * validation of every integration;
  * the private-host allowlist and the metadata block;
  * each sender against a scripted transport;
  * the Jira end-to-end retry test over real HTTP;
  * keeping credentials on edit, and refusing to keep them when the host changes;
  * the OpenAPI document's security and roles;
  * rate-limit headers;
  * the Python client against the real app.
* `argus/notify/integrations.py`: the four senders, the deduplication and the error extraction.
* `argus/notify/channels.py`: validation and the credential-keeping rule.
* `argus/security/network.py`: `assert_allowed_host` and the resolver's `private_ok_hosts`.
