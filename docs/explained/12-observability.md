# 12 — Observability (Plain-English Guide)

> Purpose: explain how you know Argus is healthy *without* someone watching it — useful for "how
> would you run this in production?" and "how would you detect an attack on your own service?".

## 1. Three questions every service must answer

| Question | Tool | In Argus |
|---|---|---|
| *Is it working, and how well?* | **Metrics** (numbers over time) | Prometheus, `/metrics` on every replica |
| *What exactly happened to this request or scan?* | **Logs** (events with context) | JSON logs with `request_id` and `investigation_id` |
| *Who needs to know, right now?* | **Alerts** (rules on metrics) | 12 Prometheus alert rules with runbooks |

A **dashboard** (Grafana) puts the metrics on one screen.

## 2. Metrics: what Argus measures

About 30 metric families, grouped the way an on-call engineer thinks:

* **API** — requests by route and status, latency histogram (p50/p95/p99), requests in flight.
* **Scans** — started (manual or scheduled), finished by status, duration, running per replica and
  across the cluster, configured capacity, findings discovered by type, scans lost to crashed replicas.
* **Collectors** — every module run by outcome (success, degraded, failed, timeout), its duration,
  circuit-breaker trips, and every outbound request to an OSINT source by outcome — including
  requests **blocked by the SSRF guard**.
* **Platform** — database reachability, checkpoint latency and failures, live WebSockets (local or
  tailing another replica), monitor runs and claims lost to other replicas, drift alerts raised.
* **Security** — rejected credentials by reason, requests refused by rate limits, audit events.
* **Process** — memory, CPU, open files per replica.

**Cardinality discipline.** Labels only ever take a small, fixed set of values: the route *template*
(`/api/investigation/{inv_id}`), never the real URL; module names; entity types. Otherwise every
investigation id or probed URL would create a new time series and eventually overwhelm Prometheus
— a classic production mistake. A test proves 404s for different ids share one series.

`/metrics` can require a bearer token (`ARGUS_METRICS_TOKEN`) or be restricted by network policy.

## 3. Logs: following one request through the system

With `ARGUS_LOG_FORMAT=json` every line is a JSON object that log platforms (Loki, Elasticsearch,
CloudWatch, Datadog) index without parsing rules:

```json
{"ts": "2026-11-14T15:00:01.281+00:00", "level": "info", "logger": "argus.access",
 "message": "GET /api/investigation/{inv_id}/paths 200 15.5ms", "route": "/api/investigation/{inv_id}/paths",
 "status": 200, "duration_ms": 15.5, "request_id": "67ca4ea2…", "instance": "argus-7d9f-abcde"}
```

* **`request_id`** comes from the load balancer's `X-Request-ID` (nginx sets one) or is generated,
  and is returned to the browser — a user reporting an error can quote it.
* **`investigation_id`** is attached to everything a scan does, including every module's warnings.
* The access log records route templates, **never query strings** (which can carry single-use
  WebSocket tickets), and Argus replaces uvicorn's own access log so each request is logged once.

## 4. Alerts: paging only when it matters

Each rule has a severity, a plain description and a **runbook** line (what to check first):

| Alert | Fires when |
|---|---|
| ArgusDown / ArgusDatabaseUnreachable | no replica reports, or the database is unreachable for 2 min |
| ArgusHighErrorRate / ArgusSlowApi | >5% server errors for 10 min / p95 latency >1 s for 15 min |
| ArgusScansFailing / ArgusReplicaLostScans / ArgusCheckpointsFailing | scans failing, lost to a crashed replica, or unable to save progress |
| ArgusAtScanCapacity | the cluster has been at its scan limit for 30 min |
| ArgusDataSourceDown / ArgusSourcesThrottling | an OSINT source keeps failing, or is rate-limiting |
| ArgusAuthFailureSpike | many invalid credentials — possible key guessing |
| ArgusEgressBlocked | the SSRF guard refused a private/metadata address |

`for:` durations prevent paging on blips. The rules are **unit-tested** with `promtool test rules`:
synthetic metric histories prove each alert fires when it should — and not when it shouldn't (for
example, failing health probes during a database outage must not *also* page as an API error spike:
that exact double-page was found during a live test and fixed).

## 5. Seeing it work

Locally, `deploy/compose/observability.yml` adds Prometheus and Grafana to the 2-replica cluster
with the data source and dashboard pre-provisioned. It was exercised end to end: both replicas
scraped, all 12 rules loaded, the dashboard rendering live traffic, and PostgreSQL stopped on
purpose — the database alert went *pending* within 20 seconds and *fired* after its 2-minute
grace period.

On Kubernetes the chart can create a **ServiceMonitor** and **PrometheusRule** (Prometheus Operator)
and the **dashboard ConfigMap** for Grafana's sidecar.
