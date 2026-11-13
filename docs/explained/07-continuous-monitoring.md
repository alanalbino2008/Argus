# 07 — Continuous Monitoring & Drift Detection (Plain-English Guide)

> Purpose: explain how Argus moves from one-off scans to watching an attack surface over time.

## 1. Why

A scan is a photograph; an organisation's attack surface is a film. Someone opens a database
port to "test something", a marketing site goes live on a new subdomain, an employee turns up in a
fresh data breach. Attackers notice these changes quickly — defenders often don't.

## 2. Comparing two scans ("drift")

`GET /api/investigation/{id}/diff` (or **Compare** in History) compares a scan with the previous
completed scan of the same target. Because Argus gives every entity a deterministic ID (a hash of
its type and value), "the same thing" is recognised across scans without guesswork.

You get:

* **New / no-longer-seen assets**, grouped by type;
* **Security-relevant changes** on assets seen both times — DMARC policy, VirusTotal detections,
  breach count, certificate expiry, header grade, service version;
* **Attack paths**: new, **escalated** (same scenario, higher risk), reduced and resolved;
* **Risk trend**: total attack-path risk before → after, e.g. *worse, 316 → 448 (+132)*.

### A design detail worth explaining

Each attack path's identity is its **rule + its subject** (e.g. *credential exposure* of
*dana@acme*), not every detail in the chain. When a second breach appears, the path is reported as
**escalated from 40 to 80** — not as one path "resolved" and a different one "opened". That flaw
was caught by testing drift on the demo data, and fixing it made the alerts meaningful.

## 3. Monitors and alerts

A **monitor** re-scans a target on a schedule (6 h, 24 h, 7 days, 30 days). After each scan, the
result is compared with the previous one; if anything *material* changed (new assets, new or
escalated paths, security-relevant fact changes) an **alert** is raised with a one-line headline:

> *acme-corp.example: 3 new attack path(s), worst: Redis exposed to the internet (high); 1 path(s)
> escalated; 4 new asset(s); 2 security-relevant change(s); 1 path(s) resolved (risk up +132)*

Safety and accountability carry over from manual scans:

* Creating a monitor requires the same **rules of engagement** — purpose and explicit
  authorisation — and the same **scope checks** (no internal targets).
* The scheduler re-checks scope **before every run**; if policy tightens, out-of-scope monitors
  are disabled and the reason is audited.
* It respects the server-wide **concurrent-scan cap** (due monitors simply wait).
* The next run is scheduled *before* the scan finishes, so a slow scan is never started twice.
* Every automated scan, alert and acknowledgement is in the **audit log**.

## 4. In the interface

* **History tab** → 🔔 *Alerts* (with an unread badge on the tab), 👁 *Monitors* (pause / resume /
  stop watching) and investigations with **Compare** and **Watch** buttons.
* **What changed** view → risk trend, path changes, asset changes; new assets glow green on the graph.

## 5. Engineering notes

* Two new tables (`monitors`, `alerts`) were added as **Alembic migration 0002** — the first real
  use of the migration workflow from Phase 4. The drift test failed until the migration existed,
  which is exactly what it's for.
* The scheduler doesn't import the web server; it receives two small functions (launch a scan,
  count running scans). That makes it testable "tick by tick": the end-to-end test creates a
  monitor, runs the baseline, makes the attack surface drift, runs again and checks the alert.
* Manual and scheduled scans share **one** launch function, so they get identical validation,
  persistence and auditing.

## 6. Questions you might be asked

* **"Why not alert on every change?"** Alert fatigue. Only *material* changes alert; removals and
  cosmetic metadata don't.
* **"How would you scale the scheduler to several servers?"** Use a database row lock (`SELECT …
  FOR UPDATE SKIP LOCKED` in PostgreSQL) or a job queue so only one instance claims each due monitor.
