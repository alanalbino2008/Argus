# Argus API guide

Everything the Argus web app does goes through a documented REST API. This guide covers how
to connect, the conventions every endpoint follows, and the integrations that send Argus's
alerts into the tools a security team already uses.

* **Reference**: open `/docs` (interactive) or `/redoc` on your Argus server. The machine-readable
  OpenAPI 3.1 document is at `/openapi.json`. Every operation lists the role it requires.
* **Python**: an official client lives in [`clients/python`](../clients/python).

## Quickstart

1. **Create an API key**: *Settings → API keys* (as a workspace admin). Choose the smallest role
   that works:
   * **viewer** reads;
   * **analyst** can also scan and edit;
   * **admin** can also manage the workspace.

   The key is shown once.
2. **Call the API**:

   ```bash
   export ARGUS_API_KEY="argus_…"
   ```

   ```bash
   curl -H "Authorization: Bearer $ARGUS_API_KEY" https://argus.example.com/api/me
   ```

3. **Run a scan and read its rating**:

   ```bash
   curl -X POST https://argus.example.com/api/scan \
     -H "Authorization: Bearer $ARGUS_API_KEY" -H "Content-Type: application/json" \
     -d '{"target": "example.com", "purpose": "Annual external assessment, ticket SEC-42", "authorized": true}'
   ```

   ```bash
   curl -H "Authorization: Bearer $ARGUS_API_KEY" https://argus.example.com/api/investigation/inv_…/rating
   ```

   The same in Python:

   ```python
   from argus_client import ArgusClient

   argus = ArgusClient("https://argus.example.com", api_key="argus_…")
   scan = argus.scan("example.com", purpose="Annual external assessment, ticket SEC-42")
   investigation = argus.wait(scan["investigation_id"])
   print(argus.rating(investigation["id"])["grade"])
   ```

`purpose` and `authorized: true` are required on every scan and monitor: Argus records why each
target was investigated and who confirmed they were allowed to, in a tamper-evident audit log.

## Conventions

### Authentication

Send the key either as `Authorization: Bearer <key>` or as `X-API-Key: <key>`. A missing,
wrong or revoked key answers `401`. Keys are stored only as SHA-256 hashes, and each key belongs
to one workspace.

### Workspaces

Data is separated into workspaces (teams, clients). A request acts in the key's workspace, or in
the one named by the `X-Argus-Workspace` header (slug or id) for people who belong to several.
Anything in a workspace you cannot see answers **404**, never `403`, so the API does not confirm
that it exists.

### Roles

The reference marks each operation with the minimum role (`x-argus-role`). Too low a role
answers `403` with the role required.

### Rate limits

| Limit | Default | Setting |
|---|---|---|
| API requests per key | 600 a minute | `ARGUS_API_REQUESTS_PER_MINUTE` (0 = unlimited) |
| Scan launches per key | 10 a minute | `ARGUS_SCANS_PER_MINUTE` |
| PDF reports per key | 10 a minute | — |

Every authenticated response carries the IETF draft headers `RateLimit-Limit`,
`RateLimit-Remaining` and `RateLimit-Reset` (seconds). A `429` also carries `Retry-After`. Wait
that long, then retry. The Python client does this for you. Limits are counted per replica. Signed-in
browser sessions are not limited, and health checks are not counted.

### Errors

Every error is JSON with a `detail` that can be shown to a person:

```json
{"detail": "Supplier not found"}
```

Validation errors (`422`) put a list in `detail`, one entry per problem, each with a `loc` (where)
and a `msg` (what). `409` means a conflict, such as a duplicate or a scan still running.

### Pagination and exports

List endpoints take `limit` (and `offset` where the list can be long). Exports return files:
* `/export/json`, `/export/csv`;
* `/export/stix` (STIX 2.1 for threat-intelligence platforms);
* `/export/navigator` (a MITRE ATT&CK Navigator layer);
* `/api/suppliers/export.csv`.

### Live progress

`GET /api/investigation/{id}` returns live counters while a scan runs. A browser can also stream
events over a WebSocket: get a one-time ticket from `POST /api/ws-ticket`, then connect to
`/ws/stream/{id}?ticket=…`.

## Breach and dark-web exposure

`GET /api/exposure` returns:
* the watched domains, with each source's last status;
* counts;
* the findings (infostealer infections, ransomware leak-site posts, breaches of the organisation,
  staff accounts in breaches).

Staff addresses are masked (`account_masked`). An analyst can add `?reveal=true`, or download
`GET /api/exposure/export.csv`. Both are recorded in the audit log.

```bash
curl -X POST https://argus.example.com/api/exposure/watches \
  -H "Authorization: Bearer $ARGUS_API_KEY" -H "Content-Type: application/json" \
  -d '{"domain": "acme.com", "organisation": "Acme Corporation", "basis": "Our corporate domain", "authorized": true}'
```

```bash
curl -X POST https://argus.example.com/api/exposure/findings/status \
  -H "Authorization: Bearer $ARGUS_API_KEY" -H "Content-Type: application/json" \
  -d '{"ids": ["exf_…"], "status": "resolved", "note": "Password reset, sessions revoked"}'
```

Exposure alerts arrive through the same destinations as drift alerts. Their `alert.exposure`
object carries the counts and the scope, and never staff addresses.

## Cases and evidence

```bash
curl -X POST https://argus.example.com/api/cases \
  -H "Authorization: Bearer $ARGUS_API_KEY" -H "Content-Type: application/json" \
  -d '{"title": "Fake charity", "purpose": "Investigating a fundraising appeal for a news story", "confirmed": true}'
```

```bash
curl -X POST https://argus.example.com/api/cases/case_…/captures \
  -H "Authorization: Bearer $ARGUS_API_KEY" -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/appeal", "note": "Before it is taken down"}'
```

The capture endpoint returns:
* the evidence's `digest` (SHA-256 of its manifest);
* its `files`, each with a SHA-256;
* whether it was `timestamped`;
* any `warnings` (e.g. a pop-up dismissed, internal addresses refused).

Other endpoints:
* `POST /api/cases/{id}/uploads` (multipart `file`, `note`) adds evidence you already hold.
* `POST /api/cases/{id}/items` adds a `note`, `entity`, `link`, `scan` or `event`.
* `POST /api/evidence/{id}/verify` recomputes every fingerprint and the custody chain.
* `GET /api/cases/{id}/export` downloads the self-verifying bundle.

Evidence files are served for download only (never rendered by Argus), except raster images.

## People and accounts

* `POST /api/scan` with a username target takes `handle_variants: true` to also search likely
  variations (jane.roe → jane_roe, janeroe…). Accounts found that way carry `variant_of` and are
  graded `possible`.
* `GET /api/investigation/{id}/people` dossiers list, for each account, `same_photo_as` (the
  platforms showing the same profile picture) and its `link` grade.

Watched accounts:

```bash
curl -X POST https://argus.example.com/api/cases/case_…/watches \
  -H "Authorization: Bearer $ARGUS_API_KEY" -H "Content-Type: application/json" \
  -d '{"platform": "GitHub", "handle": "jane-roe", "interval_hours": 24, "capture_on_change": true}'
```

* `GET /api/watchable-platforms`: `detailed` (profiles read in full) and `presence` (existence
  only).
* `GET /api/cases/{id}/watches`, `PATCH`/`DELETE /api/cases/{id}/watches/{watch_id}`.
* `POST /api/cases/{id}/watches/{watch_id}/check` checks now; `GET …/history` returns the profile
  when first seen and after each change, with `changes` (`field`, `before`, `after`).
* Changes are added to the case timeline as events, and with `capture_on_change` the profile page
  is captured as evidence (by `account-watcher`).

## Investigator safety (routes)

```bash
curl https://argus.example.com/api/opsec/routes -H "Authorization: Bearer $ARGUS_API_KEY"
# {"routes": [{"name": "tor", "kind": "tor", "anonymous": true, "description": "Tor"}], ...}
curl -X POST https://argus.example.com/api/opsec/routes/tor/check -H "Authorization: Bearer $ARGUS_API_KEY"
# {"working": true, "exit_ip": "185.220.101.7", "is_tor": true, "direct_ip": "203.0.113.9",
#  "hides_address": true, "error": null}
```

* Cases take `egress` (a route name, `""` for direct) and `opsec_mode` (`standard` or
  `anonymous`). An anonymous case needs an anonymous route.
* Captures take an optional `egress` (a route name or `direct`); by default the case's route.
  In an anonymous case, a capture that would not hide the server is refused with `409`.
* `POST /api/scan` takes `egress` and `case_id`. With a `case_id` the scan uses the case's route,
  is linked to the case, and in an anonymous case is always passive. The reply says which
  `route` was used and which modules were `skipped_for_route`.

## Compliance

`GET /api/compliance` returns, for each framework (`cyber_essentials`, `iso27001`, `nist_csf`,
`dora`):
* counts by status (`met`, `partial`, `gap`, `not_assessed`);
* every control, with its `coverage`, `status`, `reasons`, `evidence` and `gaps`.

Exports:
* `GET /api/compliance/{framework}/export.csv`, one framework;
* `GET /api/compliance/evidence.json`, every framework.

Both are audited. The mapping is outside-in evidence that supports an audit; it is not a
certification.

## Executive view and board report

`GET /api/executive?days=90` (30, 90 or 180) returns:
* `overall` (red, amber, green or grey) and a `verdict`;
* five `areas`, each with `status`, `reason` and `figures`;
* up to seven `messages`;
* `top_risks`, with owners and deadlines;
* your organisations' ratings.

`POST /api/executive/report` returns the two-page board report PDF. Its ID and SHA-256 are in the
`X-Report-Id` and `X-Report-SHA256` headers.

```bash
curl -X POST https://argus.example.com/api/executive/report -o board-report.pdf \
  -H "Authorization: Bearer $ARGUS_API_KEY" -H "Content-Type: application/json" \
  -d '{"days": 90, "tlp": "AMBER", "prepared_for": "Board of Directors"}'
```

To send it every month, create a report schedule with `"options": {"kind": "board", "period_days": 90}`
and no `target`.

## Remediation

Track a finding as a task, then move it through its lifecycle. Attack-path tasks are verified by
scans, not by hand.

```bash
curl -X POST https://argus.example.com/api/remediation \
  -H "Authorization: Bearer $ARGUS_API_KEY" -H "Content-Type: application/json" \
  -d '{"source": {"type": "attack_path", "investigation_id": "inv_…", "path_id": "path_…"}, "assignee": "alice@acme.com", "external_ref": "SEC-142"}'
```

```bash
curl -X PATCH https://argus.example.com/api/remediation/rem_… \
  -H "Authorization: Bearer $ARGUS_API_KEY" -H "Content-Type: application/json" \
  -d '{"status": "fixed", "note": "Port closed at the firewall, change CHG-881"}'
```

* `GET /api/remediation` lists tasks, most urgent first. It takes `status`, `assignee` (`me`,
  `unassigned` or a name), `severity`, `source_type` and `overdue`, and also returns metrics (SLA
  compliance, median time to verified fix, overdue counts, trend).
* Tracking a finding that already has a task returns that task with HTTP 200.
* Accepting a risk needs `accepted_until` (within a year) and a `note`.

## Webhooks

A *Webhook* destination (*Monitoring → Notifications*) receives a JSON event for every alert at
or above its severity threshold, every test, and scheduled-report summaries. Requests are
signed with the [Standard Webhooks](https://www.standardwebhooks.com/) scheme:

| Header | Meaning |
|---|---|
| `webhook-id` | The delivery id. Unchanged across retries, so drop duplicates by it. |
| `webhook-timestamp` | Unix seconds. Reject requests more than five minutes old (replays). |
| `webhook-signature` | `v1,<base64 HMAC-SHA256(secret, "<id>.<timestamp>.<body>")>`. Two are space-separated while a secret is being rotated. |

Verify **the raw body**, before parsing it:

```python
from argus_client import verify_webhook, WebhookVerificationError

try:
    verify_webhook(SIGNING_SECRET, request.headers, request.body)  # the whsec_… secret shown once
except WebhookVerificationError:
    return 401
```

Any official `standardwebhooks` library works too. Failed deliveries are retried with
exponential backoff for about seven hours, and every attempt appears in the delivery log.

An alert event looks like this:

```json
{
  "type": "alert.raised",
  "id": "evt_alt_7f3a…",
  "occurred_at": "2026-11-15T10:00:00+00:00",
  "workspace": {"id": "ws_default", "name": "Default"},
  "alert": {
    "id": "alt_7f3a…", "severity": "critical", "target": "acme.com",
    "headline": "acme.com: 2 new attack paths, worst: Redis exposed to the internet",
    "investigation_id": "inv_…", "previous_investigation_id": "inv_…", "monitor_id": "mon_…",
    "counts": {"new_paths": 2, "risk_delta": 41},
    "new_paths": [{"title": "Redis exposed to the internet", "severity": "critical"}],
    "url": "https://argus.example.com/?ws=ws_default&inv=inv_…"
  }
}
```

## Integrations

Integrations are notification destinations, so they get the same encrypted credentials,
severity thresholds, retries, delivery log and audit trail as the other destinations. Add them
under *Monitoring → Notifications → Add destination*, or with
`POST /api/notifications/channels`. Credentials are write-only. They are encrypted with
AES-256-GCM and never returned. When editing, leave a credential out to keep it. That only works
while the host stays the same: pointing a channel at a different server requires typing the
credential again, so nobody can redirect a token they never saw.

Every destination has a **Send test** button. For Jira and ServiceNow it checks the connection
and permissions without creating a ticket. The delivery log shows what each delivery created
(`SEC-12`, `INC0010001`).

### Jira (Cloud or Data Center)

Each alert becomes **one issue**. It carries the labels `argus`, `argus-<alert id>` and
`argus-severity-<severity>`. Before creating, Argus searches for the alert's label. A delivery
retried after a lost response therefore finds the existing issue instead of opening a duplicate.
Untrusted text (names found on the internet) is placed in a `{noformat}` block, so it cannot add
links or mentions.

```json
{"name": "SOC Jira", "type": "jira", "min_severity": "high",
 "destination": {"url": "https://acme.atlassian.net", "project_key": "SEC", "issue_type": "Task",
                 "email": "argus-bot@acme.com", "api_token": "…"}}
```

* **Jira Cloud**: a dedicated account's email plus an API token (id.atlassian.com → Security → API
  tokens).
* **Data Center**: leave `email` empty and use a personal access token.

The account needs *Create issues* in the project.

### ServiceNow

Each alert becomes **one incident**:
* `correlation_id` is set to `argus-<alert id>`, and Argus looks it up before creating;
* impact and urgency follow the severity (critical 1/1, high 1/2, medium 2/2, low 3/3);
* `assignment_group` is optional.

```json
{"name": "ServiceNow", "type": "servicenow",
 "destination": {"url": "https://acme.service-now.com", "username": "argus.integration",
                 "password": "…", "assignment_group": "Security Operations"}}
```

Give the integration user the `itil` role (or REST access to the `incident` table) and nothing
more.

### Splunk (HTTP Event Collector)

Alerts, scheduled reports and tests are sent to `/services/collector/event` as JSON events
(`sourcetype` `argus:event` by default). The event's `type` field distinguishes them.

```json
{"name": "Splunk", "type": "splunk", "min_severity": "low",
 "destination": {"url": "https://http-inputs-acme.splunkcloud.com", "token": "…", "index": "security"}}
```

Example search:

```text
index=security sourcetype="argus:event" type="alert.raised" | stats count by alert.severity, alert.target
```

### Microsoft Sentinel (Logs Ingestion API)

Events are sent as rows of a custom Log Analytics table through a data collection rule (DCR).
Setup:

1. Create a **data collection endpoint** (DCE) and a custom table `ArgusEvents_CL` with these
   columns:

   | Column | Type |
   |---|---|
   | `TimeGenerated` | datetime |
   | `EventType` | string |
   | `EventId` | string |
   | `Severity` | string |
   | `Target` | string |
   | `Headline` | string |
   | `WorkspaceId` | string |
   | `WorkspaceName` | string |
   | `Url` | string |
   | `Details` | dynamic |

2. Create a DCR whose input stream `Custom-ArgusEvents_CL` has the same columns, sending to the
   table.
3. Register an application (Entra ID → App registrations), create a client secret, and give the
   application the **Monitoring Metrics Publisher** role on the DCR.
4. Add the destination:

   ```json
   {"name": "Sentinel", "type": "sentinel",
    "destination": {"dce_url": "https://argus-dce-a1b2.westeurope-1.ingest.monitor.azure.com",
                    "dcr_id": "dcr-0123456789abcdef0123456789abcdef", "stream": "Custom-ArgusEvents_CL",
                    "tenant_id": "…", "client_id": "…", "client_secret": "…"}}
   ```

Argus signs in with the client-credentials flow, caches the token until shortly before it
expires, and signs in again if it is rejected. Azure Government (`.azure.us`) and Azure China
(`.azure.cn`) endpoints are recognised automatically. Example analytics rule query:

```kusto
ArgusEvents_CL
| where EventType == "alert.raised" and Severity in ("critical", "high")
| project TimeGenerated, Severity, Target, Headline, Url
```

### Self-hosted systems on private networks

Argus will not send requests to private, loopback or link-local addresses, whoever asks. This
stops a destination being used to reach internal services (server-side request forgery). For a
Splunk, Jira Data Center or ServiceNow or webhook receiver inside your network, the **operator**
lists its exact host name:

```bash
ARGUS_INTEGRATION_ALLOWED_HOSTS='["splunk-hec.corp.internal"]'
```

With Helm, set `notifications.integrationAllowedHosts`. Those hosts may resolve to private
addresses. Link-local and cloud-metadata addresses (such as `169.254.169.254`) stay blocked even
for them, at validation time and again after every DNS lookup. HTTPS with a valid certificate is
always required. TLS verification cannot be switched off.

## Security notes for API users

* Treat keys like passwords: one key per automation, the lowest role that works, revoke on
  rotation. *Last used* in Settings shows stale keys.
* Every write is recorded in the workspace's audit log with the key's name. Platform
  administrators can check the log's hash chain with `GET /api/audit/verify`.
* `/docs`, `/redoc` and `/openapi.json` describe the API but expose no data. Behind a strict
  network policy they can be blocked at the ingress.
