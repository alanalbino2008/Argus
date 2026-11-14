# 11 — Kubernetes & PostgreSQL (Plain-English Guide)

> Purpose: explain how Argus went from "one program on one computer" to "a service that keeps
> running when a server dies" — useful for "how would you deploy this in production?" and
> "what problems appear when you run several copies of an application?".

## 1. Why this matters

A single process is a single point of failure: if the machine reboots, Argus is down and any running
scan is lost. Production services run **several copies (replicas)** behind a load balancer on
**Kubernetes**, which restarts failed copies, spreads them across machines and replaces them one by
one during upgrades. The shared state moves to a proper database server, **PostgreSQL**.

## 2. The hard part: copies that don't know about each other

Running several copies of Argus revealed six real bugs. Each one shows a classic distributed-systems
problem:

1. **"Everything that was running must have crashed."** On startup, Argus marked every running scan
   as failed — sensible with one copy, wrong with several (it killed the *other* copies' scans).
   *Fix:* each scan records its **owner** and a **heartbeat**; only scans whose owner went silent are
   failed.
2. **Silent data loss in an "upsert".** Saving the investigation overwrote *every* column, erasing
   the owner and heartbeat each second. *Fix:* update only the columns being written. (Found by a
   test before it ever reached production.)
3. **Stale status.** Other copies saw a running scan as "starting" until it found something. *Fix:*
   save status changes even when nothing new was found.
4. **Forked audit chain.** Argus's tamper-evident log links each entry to the previous one's hash.
   Two copies writing at once could both link to the same entry. *Fix:* a PostgreSQL **advisory
   lock** — a named lock the database holds for the length of a transaction.
5. **Lost login tickets.** WebSocket tickets lived in one copy's memory; the next request might land
   on another copy. *Fix:* store them (hashed) in the database and redeem them with a single atomic
   `DELETE … RETURNING`.
6. **Double scheduling.** Every copy runs the scheduler, so a watched target could be scanned twice.
   *Fix:* **claim** each job with a conditional `UPDATE … WHERE next_run_at <= now` — only one copy's
   update can succeed.

And two features needed rethinking:

* **Cancel** — the button may reach a copy that isn't running the scan. It now sets a flag in the
  database that the owner reads on its next heartbeat (about a second later).
* **Live view** — the page's WebSocket may connect to a copy that isn't running the scan. That copy
  now **tails the database**, streaming findings as the owner saves them.

If a copy freezes, the others notice the missing heartbeat, mark its scans failed, and **fence** it:
should it wake up, its next heartbeat tells it to stop rather than carry on.

## 3. Kubernetes in practice (the Helm chart)

**Helm** packages all the Kubernetes objects Argus needs into one installable, configurable chart:

* **Deployment** — two or more Argus pods, spread across machines and zones, replaced one at a time
  during upgrades (`maxUnavailable: 0`, so capacity never drops).
* **Probes** — *startup* (still booting), *readiness* (database reachable — otherwise taken out of
  the load balancer) and *liveness* (process alive — otherwise restarted). Liveness deliberately
  ignores the database, so a database outage doesn't cause every pod to restart in a loop.
* **Init container** — runs the database migrations before the new version starts.
* **PodDisruptionBudget** — node maintenance can never take all pods down at once.
* **HorizontalPodAutoscaler** — optional; adds pods under load, removes them slowly.
* **NetworkPolicy** — a firewall per pod: Argus may reach the internet (it's an OSINT tool) but not
  private networks or the cloud metadata service, so a malicious redirect can't pivot into the
  cluster. This backs up the SSRF protection in Argus's own code (defence in depth).
* **Hardened pods** — non-root, read-only filesystem, no Linux capabilities, no Kubernetes API token.
* **Secrets** — generated once and kept across upgrades, or supplied from your own secret store.

## 4. How it was tested

* The **entire test suite runs against real PostgreSQL 16** as well as SQLite, locally and in CI.
* **Cluster tests** simulate two pods with two independent database connections: tickets across
  pods, exactly-once scheduling, concurrent audit writes, cross-pod cancel, crash detection and
  fencing, and live streaming of another pod's scan.
* A **Docker Compose cluster** (PostgreSQL + 2 replicas + nginx) was exercised end to end: load
  balancing, status seen from both replicas, cancel sent to the other replica, and a replica
  *frozen mid-scan* — the survivor marked its scan failed within 30 seconds.
* The chart is **linted, schema-validated** in several configurations, and in CI **installed on a
  real Kubernetes cluster (kind)**, checked with `helm test` and **rolled under traffic**.
