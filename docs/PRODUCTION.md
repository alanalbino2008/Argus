# Go-live checklist

Work through this before you put Argus in front of real users. Installation is covered in
[`DEPLOYMENT.md`](DEPLOYMENT.md); this page lists what makes an installation production-grade.

## 1. Run the preflight

```bash
kubectl -n argus exec deploy/argus -- argus --preflight        # Kubernetes
docker exec argus argus --preflight                            # Docker
```

The preflight runs the same checks a production server runs every time it starts. The container image
and the Helm chart both run with `ARGUS_ENVIRONMENT=production`, so the server **refuses to start**
while any *error* remains, and the log names the fix. *Warnings* do not stop the server but are worth
reading.

| Check | Level | Why |
|---|---|---|
| Authentication on | error | With it off, every caller is an administrator |
| `FORWARDED_ALLOW_IPS` is not `*` | error | `*` lets any client forge its IP address, getting past network allow-lists, rate limits and sign-in lockouts |
| A shared `ARGUS_ENCRYPTION_KEY` on PostgreSQL | error | Replicas must decrypt each other's integration secrets |
| `ARGUS_PUBLIC_URL` is `https://` | error | Otherwise sign-in cookies and API keys cross the network unencrypted |
| No `*` in `ARGUS_CORS_ORIGINS` | error | `*` lets any website call the API from a visitor's browser |
| PostgreSQL, not SQLite | warning | SQLite means one server with no failover |
| JSON logs, SMTP, metrics token, public URL set | warning | Needed for operations, email and monitoring |

## 2. Infrastructure

- [ ] **PostgreSQL 14+** (managed), with automated backups, point-in-time recovery and a standby.
      Connect with `?ssl=require`.
- [ ] **HTTPS** at the ingress or load balancer (TLS 1.2+), with `ARGUS_PUBLIC_URL` set to that address.
- [ ] **Trusted proxies:** `config.trustedProxies` (Helm) or `FORWARDED_ALLOW_IPS` (Docker) set to the
      ingress or load balancer subnet only.
- [ ] **Two or more replicas**, with the PodDisruptionBudget and topology spread from the chart. Turn on
      autoscaling for uneven load.
- [ ] **Egress:** the chart's NetworkPolicy blocks private ranges, so allow the database's CIDR
      (`networkPolicy.databaseCIDRs`) and any internal integrations.
- [ ] **Resources:** start from the chart's requests and limits. One replica handled about 90
      requests/s of mixed traffic at around 280 MB of memory in the release drill (below).

## 3. Secrets and access

- [ ] Secrets come from your secret store (`secrets.existingSecret`), not from `values.yaml` in git.
- [ ] Back up `ARGUS_ENCRYPTION_KEY` with the database. Without it, stored integration secrets cannot be
      read.
- [ ] Single sign-on configured (OIDC), with MFA enforced at the identity provider.
- [ ] Personal admin keys created, then the **bootstrap key revoked** (*Settings → API keys*).
- [ ] An API-key policy set (maximum lifetime, network restrictions for automation keys).
- [ ] Optional: `ARGUS_API_DOCS_ENABLED=false` to hide the interactive API reference.

## 4. Monitoring and response

- [ ] Prometheus scrapes `/metrics` with `ARGUS_METRICS_TOKEN`. Load the bundled alert rules and Grafana
      dashboard (`metrics.serviceMonitor`, `metrics.prometheusRule`, `metrics.grafanaDashboard`).
- [ ] Logs (JSON, with request ids) shipped to your log platform. Stream the audit log to your SIEM.
- [ ] Someone receives the alerts: availability, error rate, database down, stuck scans.
- [ ] Contact details for reporting vulnerabilities are published (see `SECURITY.md`).

## 5. Prove it before launch

- [ ] **Restore drill:** restore a backup into a scratch database and run `argus --check` on it
      (see `docs/explained/97-backup-restore-drills.md`).
- [ ] **Upgrade drill:** `helm upgrade` to the same version under traffic, and confirm there are no failed
      requests.
- [ ] **Failover drill:** delete one pod under traffic. The others carry on, and its scans are recorded
      as interrupted.
- [ ] `helm test argus` passes.

## What every release is checked for

Every commit runs these checks in CI, and any failure blocks it:

- **Code:** lint, types, and the full test suite on Python 3.10 to 3.13 and on PostgreSQL 16.
- **Accessibility:** WCAG 2.1 AA checked with axe.
- **Kubernetes:** the Helm chart installed on a real cluster (kind), its tests run, and a rolling restart
  under traffic.
- **Dependencies:** every Python package checked for known CVEs, in both the tooling and the exact
  versions shipped in the image (`requirements.lock`). A stale lock fails the build.
- **Image:**
  - started read-only, without Linux capabilities, and must report healthy;
  - must contain no secrets, source tree or package installer;
  - must refuse to start with an unsafe configuration;
  - scanned with Trivy (a fixable critical CVE fails the build) and given a software bill of materials.
- **Releases:** images are signed (Sigstore) and carry SLSA build provenance.

### Release drill (1.127.0)

Two replicas ran on PostgreSQL 16, read-only and without capabilities. Under 40 concurrent clients for
60 seconds, with a mix of reads, writes and scans, they served **10,917 requests with zero errors**:
p95 of 280–400 ms for reads and writes, and under 0.9 s to launch a scan. Memory held at about 282 MB per
replica. Shutdown on SIGTERM was clean and took 0.6 s.
