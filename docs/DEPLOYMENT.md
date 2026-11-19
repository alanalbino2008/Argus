# Deploying Argus

Three supported shapes, all from the same container image:

| Shape | Database | Use it for |
|---|---|---|
| `docker compose up` | SQLite on a volume | A laptop, a lab, a single VM |
| `deploy/compose/cluster.yml` | PostgreSQL | A VM or two with high availability of the API |
| Helm chart (`deploy/helm/argus`) | PostgreSQL (managed, or bundled for evaluation) | Kubernetes, production |

---

## 1. Kubernetes with Helm

### Quick evaluation (bundled PostgreSQL)

```bash
helm install argus deploy/helm/argus --namespace argus --create-namespace
kubectl -n argus rollout status deploy/argus
kubectl -n argus port-forward svc/argus 8000:80        # http://localhost:8000
kubectl -n argus get secret argus -o jsonpath='{.data.bootstrap-admin-key}' | base64 -d; echo
```

The bundled database is a single pod with a persistent volume — fine to try Argus, not for
production (no backups, no failover).

### Production (managed PostgreSQL)

1. Create a PostgreSQL 14+ database (Amazon RDS, Google Cloud SQL, Azure Database for PostgreSQL…)
   with backups and high availability enabled, and a dedicated user that owns the database.
2. Store the connection URL in a Secret (`ssl=require` keeps traffic encrypted):

   ```bash
   kubectl -n argus create secret generic argus-db \
     --from-literal=database-url='postgresql+asyncpg://argus:PASSWORD@db.internal:5432/argus?ssl=require'
   ```

3. Optional: keep application secrets in your own Secret too (keys `bootstrap-admin-key`,
   `github-token`, `virustotal-api-key`, `hibp-api-key`, `shodan-api-key`), e.g. synced from a vault.
4. Install:

   ```bash
   helm install argus deploy/helm/argus -n argus \
     --set externalDatabase.existingSecret=argus-db \
     --set networkPolicy.databaseCIDRs='{10.20.0.0/16}' \
     --set ingress.enabled=true --set ingress.className=nginx \
     --set ingress.host=argus.example.com --set ingress.tls.enabled=true \
     --set autoscaling.enabled=true
   ```

   Released charts are also published as `oci://ghcr.io/alanalbino2008/charts/argus`.

`networkPolicy.databaseCIDRs` matters: private address ranges are blocked for Argus's egress by
default (see *Security* below), so the database's range must be allowed explicitly.

### What the chart sets up

| Concern | How |
|---|---|
| Availability | 2+ replicas spread across nodes and zones; PodDisruptionBudget; rolling updates with `maxUnavailable: 0` |
| Scaling | Optional HPA on CPU, scaling in slowly (a removed pod cancels the scans it was running) |
| Health | `startupProbe` and `livenessProbe` on `/api/live` (process only); `readinessProbe` on `/api/health` (database reachable). A database outage removes pods from the Service without restarting them |
| Shutdown | `preStop` drain, then running scans are cancelled and persisted within the grace period |
| Migrations | An init container runs `argus --migrate` before each pod starts; a PostgreSQL advisory lock makes concurrent runs safe |
| Configuration | ConfigMap + Secret; pods roll automatically when either changes |
| Security | Non-root UID 10001, read-only root filesystem, all capabilities dropped, `RuntimeDefault` seccomp, no service-account token, NetworkPolicies |

### Day-2 operations

* **Upgrade**: `helm upgrade argus deploy/helm/argus -n argus --reuse-values`. New pods migrate the
  schema first; migrations are written to be backward compatible with the previous release (add
  columns and tables, never drop in the same release) so old and new pods can run side by side
  during the rollout.
* **Check**: `helm test argus -n argus` verifies the API is healthy, the database is reachable and
  traffic reaches several replicas.
* **Scale**: `--set replicaCount=4`, or enable autoscaling.
* **Back up**: back up PostgreSQL (managed snapshots or `pg_dump`). Argus keeps no other state —
  pods are disposable.
* **Rotate the bootstrap key**: create personal keys in *Settings → API keys*, then revoke the
  bootstrap key there.

### Single sign-on

Register Argus as a **confidential web application** (OpenID Connect, authorization code flow)
at your identity provider, with redirect URI **`https://<your Argus host>/auth/oidc/callback`**,
then:

```bash
kubectl -n argus create secret generic argus-secrets --from-literal=oidc-client-secret='<client secret>'
helm upgrade argus deploy/helm/argus -n argus --reuse-values \
  --set secrets.existingSecret=argus-secrets \
  --set sso.enabled=true --set sso.issuer=<issuer> --set sso.clientId=<client id> \
  --set sso.displayName=<label> --set 'sso.allowedDomains={acme.com}' --set 'sso.adminGroups={argus-admins}'
```

| Provider | Issuer | Notes |
|---|---|---|
| Google Workspace | `https://accounts.google.com` | No groups claim: use `adminEmails` and roles in *Settings*. `allowedDomains` matches the Workspace domain (`hd`). |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant-id>/v2.0` | Set `requireVerifiedEmail: false` (Entra omits `email_verified`). Add a *groups* or *app roles* claim to the ID token; set `roleClaim: roles` for app roles. |
| Okta | `https://<org>.okta.com` (or a custom authorization server) | Add a `groups` claim to the ID token. |
| Keycloak | `https://<host>/realms/<realm>` | Add a *Group Membership* mapper (`full.path` off). A Keycloak inside your network also needs `networkPolicy.internalEgress`. |

* Roles: highest of `adminGroups` / `analystGroups` / `viewerGroups` found in `roleClaim`; otherwise
  `defaultRole` (`none` refuses the user). When group mapping is configured the provider is the source
  of truth and roles are refreshed at every sign-in; otherwise administrators set roles in *Settings*.
* `adminEmails` grants admin to named people — use it to bootstrap the first administrators.
* Sessions last `sessionTtlHours` (8 h). Disabling a user in *Settings* signs them out everywhere at once.
* API keys keep working for automation and break-glass access.

### Team workspaces

Each team gets its own workspace: investigations, monitors, alerts, API keys and audit entries
are invisible to other workspaces. A platform admin creates workspaces in *Settings*, and
workspace admins add members there by email. With SSO, the membership can come from the identity
provider:

```bash
helm upgrade argus deploy/helm/argus -n argus --reuse-values \
  --set sso.defaultWorkspace=default --set 'sso.workspaceGroups.argus-red-team=red-team'
```

* `defaultWorkspace`: every SSO user joins it on first sign-in (`""` = admins add people by hand).
* `workspaceGroups`: group → workspace slug, mirrored at every sign-in (leaving the group removes the
  membership).
* Automation: API keys belong to the workspace they were created in. Scripts may send
  `X-Argus-Workspace: <slug or id>`, but a bound key only ever sees its own workspace.

### Alert notifications (Slack, Teams, email, webhooks)

Workspace admins add destinations in *Monitoring → Notifications*. The operator only needs to:

* **Keep the encryption key safe.** The chart generates `encryption-key` in its Secret on first
  install and keeps it across upgrades. It encrypts destination URLs and signing secrets in the
  database, so back it up together with the database. With `secrets.existingSecret`, add an
  `encryption-key` entry (32+ random characters) yourself. To rotate it, put the old value in
  `ARGUS_ENCRYPTION_PREVIOUS_KEYS` (`config.extraEnv`) and set a new key.
* **Set `publicUrl`** (or an ingress host) so messages link back to Argus.
* **Email (optional)**:

  ```bash
  helm upgrade argus deploy/helm/argus -n argus --reuse-values \
    --set notifications.smtp.host=smtp.office365.com --set notifications.smtp.username=argus@acme.com \
    --set notifications.smtp.from=argus@acme.com --set secrets.smtpPassword='<password>'
  ```

  A relay inside your network also needs `networkPolicy.internalEgress` (port 587, 465 or 25).

Slack, Teams and public webhooks need nothing else: they use the normal internet egress, and
private addresses stay blocked. Watch `ArgusNotificationsFailing` and `ArgusNotificationBacklog`.

### Integrations (Jira, ServiceNow, Splunk, Microsoft Sentinel)

Cloud-hosted integrations (Jira Cloud, ServiceNow, Splunk Cloud, Sentinel) need nothing from the
operator. A **self-hosted** instance on a private network is refused unless you list its exact
host name. Wildcards are not accepted, and link-local and metadata addresses stay blocked:

```bash
helm upgrade argus deploy/helm/argus -n argus --reuse-values \
  --set 'notifications.integrationAllowedHosts={splunk-hec.corp.internal,jira.corp.internal}'
```

The pods also need a route there: add the hosts' network to `networkPolicy.internalEgress`. HTTPS
with a certificate the pods trust is required. Mount an internal CA bundle and set `SSL_CERT_FILE`
through `config.extraEnv` if needed. Setup for each integration is in [`API.md`](API.md#integrations).

### Breach and dark-web exposure

Exposure monitoring runs on every replica and needs no setup for its public sources: the HIBP
breach catalogue and the ransomware.live feed. The chart's network policy already allows the
public internet. Behind your own egress firewall, allow `haveibeenpwned.com` and `api.ransomware.live`
on port 443.

* **Breached staff accounts and infostealer logs** need a Have I Been Pwned API key
  (`secrets.hibpApiKey`). Stealer logs need a plan that includes them. HIBP only answers for
  domains verified in its domain search dashboard. Verify each domain your teams will watch.
* `config.ransomwareFeedUrl: ""` turns the ransomware feed off, and `config.exposureMonitoring:
  false` stops the loop.
* Closed findings are deleted after `ARGUS_EXPOSURE_RETENTION_DAYS` (default 365, via
  `config.extraEnv`). Set it to your data-retention policy.

### Evidence capture

Screenshots need a headless browser on the server. Argus looks for one automatically
(`ARGUS_CAPTURE_BROWSER=auto`) and prefers **chrome-headless-shell** (from Chrome for Testing):
* it has no Google services, so it never reveals investigation activity to Google;
* full Chromium or Chrome also work.

Without a browser, pages are still captured (response, text, headers) but with no screenshot,
and the capture says so.

* `ARGUS_EVIDENCE_TIMESTAMP_URL`: an RFC 3161 timestamp authority (for example a commercial TSA,
  or `https://freetsa.org/tsr`) for independent proof of when evidence existed. Only digests are
  sent.
* `ARGUS_EVIDENCE_MAX_UPLOAD_MB` (default 25) limits uploaded evidence files.
* Evidence is stored in the database. Back it up like any other case material, and size the
  database for screenshots (typically 0.2–3 MB per capture).

### People and accounts

* **Community username catalog.** By default Argus downloads the WhatsMyName catalog
  (`ARGUS_USERNAME_CATALOG_URL`, CC BY-SA 4.0) when a username is first searched, and caches it
  for a week (`ARGUS_USERNAME_CATALOG_TTL_HOURS`). Offline installs can point
  `ARGUS_USERNAME_CATALOG_FILE` at a downloaded copy; set the URL to `""` to use only the built-in
  sites. If the catalog can't be loaded, the built-in sites are still searched.
* **Watched accounts** are checked by every replica's background loop (each due watch is claimed
  by exactly one). `ARGUS_ACCOUNT_WATCH_ENABLED` (default true) turns it off, and it also stops
  when `ARGUS_MONITORS_ENABLED` is false. `ARGUS_ACCOUNT_WATCH_POLL_SECONDS` (default 60) is how
  often due watches are looked for.

### Crypto investigations

All sources are free and need no keys:
* `ARGUS_BITCOIN_API_URL` (default `https://mempool.space/api`): any Esplora-compatible API.
  Point it at your own node's Esplora to keep lookups in-house.
* `ARGUS_EVM_CHAINS` (default Ethereum): Blockscout instances by chain, e.g.
  `{"ethereum": "https://eth.blockscout.com", "base": "https://base.blockscout.com"}`. Each extra
  chain is one more look-up per wallet.
* `ARGUS_SANCTIONS_SDN_URL` and `ARGUS_SANCTIONS_COMMENTS_URL` (OFAC's own files, cached for a
  day), or `ARGUS_SANCTIONS_FILE`: a folder with saved copies of `sdn.csv` and `sdn_comments.csv`
  for offline installs.
* `ARGUS_CRYPTO_COUNTERPARTIES` (default 12): counterparties kept per wallet.

### Companies, sanctions and leaks

Free sources, no keys:
* GLEIF (`ARGUS_GLEIF_URL`) and the ICIJ Offshore Leaks Database (`ARGUS_OFFSHORE_LEAKS_URL`).
  Offshore Leaks data is under the Open Database Licence: results credit ICIJ.
* Sanctions lists: `ARGUS_SANCTIONS_SDN_URL` and `ARGUS_SANCTIONS_ALT_URL` (US),
  `ARGUS_UK_SANCTIONS_URL` and `ARGUS_UN_SANCTIONS_URL`, cached daily. For offline installs, a
  saved-copy folder `ARGUS_SANCTIONS_FILE` holding `sdn.csv`, `alt.csv`,
  `UK-Sanctions-List.csv` and `consolidated.xml`. Each list loads on its own; one failing never
  stops the others.
* SEC EDGAR: set `ARGUS_SEC_USER_AGENT` to `"Your Organisation contact@example.com"`, as the SEC
  requires.

**UK Companies House** needs a free key (from developer.company-information.service.gov.uk):
* on the **account service**, `ARGUS_COMPANIES_HOUSE_API_KEY` is the key Argus Connect uses for
  every subscriber's lookups, paid for in credits;
* on any **other** Argus (or Argus Personal), setting it makes lookups go directly, privately and
  without credits.
* `ARGUS_COMPANIES_HOUSE_OFFICER_LIMIT` (default 8): directors whose other companies are looked up
  per company.

**Web mentions** (where a phone number or email address appears on the web) use the Brave Search
API (from api-dashboard.search.brave.com):
* on the **account service**, `ARGUS_WEB_SEARCH_API_KEY` is the key Argus Connect uses for every
  subscriber's searches, at 1 credit each (refunded when nothing is found);
* on any **other** Argus (or Argus Personal), setting it makes searches go directly, privately and
  without credits.

**The case vault** (Argus Personal and other single-computer installations on SQLite) is turned
on by the investigator in Settings, with their own passphrase; there is nothing to configure.
`ARGUS_VAULT_IDLE_MINUTES` (default 15; 0 = never) sets how long it stays unlocked without
activity. It is not offered on PostgreSQL: protect shared database servers with their own
encryption at rest.

**The website crawler** (`site_crawler`) reads a target website's pages, obeying robots.txt:
* `ARGUS_CRAWL_MAX_PAGES` (default 40, up to 500): the most pages read on one site;
* `ARGUS_CRAWL_DELAY_SECONDS` (default 0.5): the pause between pages, so the site is never strained.
It contacts the website itself, so passive-only scans and anonymous cases skip it. It never visits
other websites the site links to.

**The AI analyst** (Claude, by Anthropic) needs a Claude API key (from console.anthropic.com):
* on the **account service**, `ARGUS_ANTHROPIC_API_KEY` is the key Argus Connect uses for every
  subscriber's analyst requests, paid for in credits (brief and extract 10, report 20, plus 2 per
  50,000 characters beyond the first 50,000; refunded on failure). The case material passes
  through and is never stored or logged;
* on any **other** Argus (or Argus Personal), setting it sends case material straight to
  Anthropic, without credits.
* `ARGUS_ANALYST_MODEL` (default: the newest Claude Opus model the key can use),
  `ARGUS_ANALYST_EFFORT` (`low` to `max`, default `high`), `ARGUS_ANALYST_MAX_CHARS` (default
  400,000: the most case material sent in one request; documents beyond it are listed as left out).

**Argus credits**: each plan's monthly allowance (trial 50, personal 500, professional 2,000)
renews on the 1st; purchased credits never expire. A payment provider's webhook handler adds
purchased credits with `POST /api/accounts/{id}/credits` (`kind: purchase`).

### Argus accounts and Argus Personal

**The account service** (your central server) creates accounts and signs licences:

```bash
argus --generate-licence-keys      # prints a signing key (secret) and its public key
```

Set on the central deployment:
* `ARGUS_ACCOUNT_SERVICE_ENABLED=true`;
* `ARGUS_LICENCE_SIGNING_KEY=<secret key>` (Helm: `secrets.licenceSigningKey`);
* `ARGUS_PUBLIC_URL=https://accounts.example.com`: this exact address is written into each
  licence, and Argus Personal checks it;
* optionally `ARGUS_ACCOUNT_SIGNUP_ENABLED=true` (open trials), `ARGUS_TRIAL_DAYS` and
  `ARGUS_LICENCE_OFFLINE_DAYS`.

Plans (trial, personal, professional), statuses (trialing, active, past_due, cancelled,
suspended) and the paid-until date are kept in step with Stripe automatically (below); an admin
can also change them with `PATCH /api/accounts/{id}`. Back up the signing key: if it changes,
every Argus Personal installation needs the new public key.

#### Payments with Stripe

1. In the Stripe dashboard, create a product for each plan with a **recurring** price (Personal,
   Professional) and, for credit packs, products with **one-off** prices.
2. Add a webhook endpoint `https://accounts.example.com/api/billing/webhook` for the events
   `checkout.session.completed`, `checkout.session.async_payment_succeeded`,
   `customer.subscription.created`, `customer.subscription.updated`,
   `customer.subscription.deleted`, and for refunds and disputes `charge.refunded`,
   `charge.dispute.created` and `charge.dispute.closed`.
3. Turn on the **customer portal** (Settings → Billing → Customer portal) so customers can update
   their card, see invoices, change plan and cancel.
4. Set on the account service:
   * `ARGUS_STRIPE_SECRET_KEY=sk_live_...` (Helm: `secrets.stripeSecretKey`);
   * `ARGUS_STRIPE_WEBHOOK_SECRET=whsec_...` (Helm: `secrets.stripeWebhookSecret`);
   * `ARGUS_STRIPE_PRICE_PERSONAL`, `ARGUS_STRIPE_PRICE_PROFESSIONAL`: the plans' price ids;
   * `ARGUS_STRIPE_CREDIT_PACKS=500=price_...,2000=price_...` (credits = price id);
   * optionally `ARGUS_BILLING_RETURN_URL`: where customers land after paying, when they did not
     start from Argus Personal.

Try it first with test keys (`sk_test_...`) and Stripe's test cards. Card details never reach
Argus: customers pay on Stripe's own pages.

#### Account emails

With an SMTP server set (`ARGUS_SMTP_HOST` and friends, as for notifications), the account
service emails account holders: welcome, payment received, payment failed, plan changed,
cancellation confirmed, subscription ended, credits added, trial ending and trial ended
reminders, and password resets ("Forgot your password?" on Argus Personal's sign-in screen opens
`https://accounts.example.com/reset-password`). Optional settings:

* `ARGUS_ACCOUNT_EMAIL_FROM`: the sender (default `ARGUS_SMTP_FROM`), e.g.
  `Argus <hello@example.com>`. Set up SPF and DKIM for its domain so emails aren't marked as spam;
* `ARGUS_SUPPORT_EMAIL`: shown in each email and used as Reply-To;
* `ARGUS_ACCOUNT_EMAILS_ENABLED=false` turns them off.

`ARGUS_PUBLIC_URL` must be the account service's public address: links in emails use it.

**Argus Personal** (each investigator's computer):

```bash
pip install argus-osint
ARGUS_ACCOUNT_SERVER_URL=https://accounts.example.com ARGUS_LICENCE_PUBLIC_KEY=<public key> argus --personal
```

* It listens on `127.0.0.1` only, keeps its database in the user's application-data folder
  (`ARGUS_HOME` overrides it) and opens the browser.
* The account service only ever receives the email and password at sign-in, a random device id
  and name, and the licence when renewing. Never case data.
* It renews daily, works offline for `ARGUS_LICENCE_OFFLINE_DAYS`, and turns read-only (never
  locked) when a subscription is not current.

### Maps

* `ARGUS_MAP_TILE_URL` (default OpenStreetMap's tile server): map images. The **server** fetches
  them and serves them to the browser, caching 2,000 tiles per replica. For heavy use, point it at
  your own tile server or a commercial provider, as the OpenStreetMap tile policy asks. Set it to
  `""` to draw maps without a background.
* `ARGUS_MAP_ATTRIBUTION`: the credit shown on maps (keep the provider's required attribution).
* `ARGUS_GEOCODER_URL` (default OpenStreetMap's Nominatim): address look-up, used only when an
  investigator presses **Find on map**, at most once a second. Point it at your own Nominatim to
  keep addresses in-house, or set it to `""` to switch look-ups off.

### Investigator safety (Tor, VPN, proxy routes)

The people being investigated can see every request in their logs. Routes send captures and
scans through Tor, a VPN or a proxy instead. A route is any **HTTP CONNECT proxy**:

```bash
ARGUS_EGRESS_ROUTES='[
  {"name": "tor", "kind": "tor", "url": "http://127.0.0.1:9080", "description": "Tor"},
  {"name": "vpn-de", "url": "http://user:pass@de.vpn.example:3128", "anonymous": true}
]'
```

* **Tor**: run Tor next to Argus with `HTTPTunnelPort 9080` in its `torrc` (Tor 0.3.2 or newer),
  for example as a sidecar container. Tor routes are anonymous by default, and host names are
  passed to Tor unresolved.
* **VPN or proxy** (`kind` `proxy`, the default): set `"anonymous": true` only if whoever runs it
  is trusted not to reveal who uses it.
* Route URLs may carry credentials: keep the variable in a secret. In Kubernetes set
  `secrets.egressRoutes`; if the route runs in the cluster, allow it under
  `networkPolicy.internalEgress`.
* `ARGUS_EGRESS_CHECK_URL` (default `https://check.torproject.org/api/ip`) is the IP-echo service
  the route test asks. Any service that answers with the caller's address, as JSON (`IP`, `ip`
  or `origin`) or plain text, works.
* Routes carry web traffic. DNS lookups by scan modules still use the server's normal resolver:
  the subject's name servers see the **resolver's** address. Point the server at a shared public
  resolver (not one running on the server itself) so that address says nothing about you.

### Remediation

Remediation needs no setup. Its clock (overdue alerts, expiring risk acceptances) runs on every
replica alongside the monitor scheduler (`config.monitorsEnabled`). Each overdue task is claimed
once across replicas. Closed tasks are kept for two years of metrics, then deleted.

### Client reports

Reports need no setup: the image includes the fonts, and every report's fingerprint is
recorded in the database.

* Set `publicUrl` so the verification address printed in each report is the one clients can
  reach.
* `GET /api/reports/verify/<sha256>` is intentionally reachable **without signing in**, so
  recipients can check a report. It only answers for the exact file and is rate-limited. If
  Argus sits behind a VPN-only ingress, either expose this path publicly or verify reports for
  clients on request.

### Monitoring

```bash
helm upgrade argus deploy/helm/argus -n argus --reuse-values \
  --set metrics.serviceMonitor.enabled=true \
  --set metrics.serviceMonitor.labels.release=kube-prometheus-stack \
  --set metrics.prometheusRule.enabled=true \
  --set metrics.grafanaDashboard.enabled=true
```

* Every pod serves Prometheus metrics at `/metrics` (port 8000). Without the Prometheus Operator,
  pods carry `prometheus.io/scrape` annotations instead.
* `secrets.metricsToken` makes `/metrics` require a bearer token; the ServiceMonitor sends it.
* Logs are JSON by default in the chart (`config.logFormat`), one object per line with
  `request_id`, `investigation_id` and `instance` — ship them with your usual collector.
* Alert rules: `files/alerts.yaml` in the chart (unit tests: `files/alerts.test.yaml`).
  Dashboard: `files/argus-dashboard.json`, generated by `deploy/observability/build_dashboard.py`.

---

## 2. Clustered with Docker Compose

```bash
cp deploy/compose/.env.example deploy/compose/.env    # set POSTGRES_PASSWORD and ARGUS_BOOTSTRAP_ADMIN_KEY
docker compose -f deploy/compose/cluster.yml up -d --build
```

Starts PostgreSQL, a one-off `argus --migrate` job, two Argus replicas and an nginx load balancer
on port 8000 (round-robin — no sticky sessions needed).

Add monitoring with the observability overlay (set `GRAFANA_ADMIN_PASSWORD` in `.env`):

```bash
docker compose -f deploy/compose/cluster.yml -f deploy/compose/observability.yml up -d
```

Grafana on http://localhost:3000 opens on the *Argus OSINT* dashboard; Prometheus on
http://localhost:9090 shows targets, rules and alerts.

---

## 3. How several replicas work together

Replicas share nothing but PostgreSQL:

| Problem with several replicas | Solution |
|---|---|
| A scan runs in one pod; others must know it is alive | The owner records itself and refreshes a **heartbeat** about once a second |
| A pod crashes mid-scan | Every pod runs a **janitor**: scans without a heartbeat for `ARGUS_SCAN_STALE_SECONDS` (default 120) are marked failed. A pod that was only frozen is **fenced**: it stops the scan on its next heartbeat |
| A pod restarts | It fails only *its own* earlier scans — never other pods' live scans |
| "Cancel" lands on the wrong pod | It sets a flag in the database; the owner sees it on its next heartbeat |
| The browser's WebSocket lands on the wrong pod | That pod **tails the database**, streaming new findings as the owner checkpoints them |
| WebSocket tickets issued by one pod | Stored (hashed) in the database; redeemed atomically, once, anywhere |
| Every pod runs the monitor scheduler | Each due monitor is **claimed** with a conditional UPDATE: exactly one pod starts it |
| Two pods append to the tamper-evident audit log | A transaction-scoped **advisory lock** keeps the hash chain linear |
| Two pods start at once and migrate | An **advisory lock** serialises migrations |
| The concurrent-scan cap | Counted across the cluster (live heartbeats), not per pod |

Per-key rate limits are enforced per pod: scan launches (`ARGUS_SCANS_PER_MINUTE`) and API
requests (`ARGUS_API_REQUESTS_PER_MINUTE`, `config.apiRequestsPerMinute`). The effective limit is
therefore that value × replicas.

---

## 4. Security notes

* **Egress**: OSINT needs the internet, but a scanner that can reach the cluster's own network is an
  SSRF risk. Argus already refuses private destinations in code; the NetworkPolicy adds a second,
  independent layer: egress to `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`
  (cloud metadata) and `100.64.0.0/10` is blocked, except DNS and the database.
* **Secrets** live only in Kubernetes Secrets (or your own), never in values files committed to Git.
* Put Argus behind TLS (Ingress with a certificate) — API keys travel in an `Authorization` header.
* Set `config.corsOrigins` only if another web app must call the API from a browser.
