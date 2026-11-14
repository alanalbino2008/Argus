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

Per-key scan rate limits (`ARGUS_SCANS_PER_MINUTE`) are enforced per pod, so the effective limit
is that value × replicas.

---

## 4. Security notes

* **Egress**: OSINT needs the internet, but a scanner that can reach the cluster's own network is an
  SSRF risk. Argus already refuses private destinations in code; the NetworkPolicy adds a second,
  independent layer: egress to `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`
  (cloud metadata) and `100.64.0.0/10` is blocked, except DNS and the database.
* **Secrets** live only in Kubernetes Secrets (or your own), never in values files committed to Git.
* Put Argus behind TLS (Ingress with a certificate) — API keys travel in an `Authorization` header.
* Set `config.corsOrigins` only if another web app must call the API from a browser.
