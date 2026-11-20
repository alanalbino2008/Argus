# 69 — Fingerprint watches

## Why

A favicon hash, JARM, HASSH or certificate shared by a handful of servers is often one operator's
infrastructure: one phishing kit, one C2 framework, one actor's habits. Looking it up once
(Phases 63 and 67) shows today's servers. Operators keep building, though, and the useful moment is
when they stand up the *next* server, often before it is used.

## What it does

On a fingerprint in the graph's details panel, **Watch for new servers** (next to each search
engine that has a key) asks Argus to re-run that fingerprint's search on a schedule:

1. **First run: the baseline.** It runs straight away and records the servers sharing the
   fingerprint today. No alert: those are what you already looked at.
2. **Every day (or week) after that**, it runs again. Servers it has not seen before (an address,
   or a known address on a new port) raise **one alert per run**, linked to the investigation the
   watch was started from, naming up to 20 of the new servers.

Alerts arrive wherever the team's alerts go: the Monitoring page, Slack, Teams, email and webhooks.

**Monitoring → Watched fingerprints** lists each watch: the fingerprint and its query, how many
servers it knows (and how many share it in all), when it last ran, any error, **Run now**, and
remove.

## Credits and limits

* Each run is one search: one Shodan query credit, or whatever the Censys plan charges.
* The search is always the entity's own query, built by Argus, never free text.
* At most 50 watches per workspace, and up to 2,000 remembered servers per watch.
* With several replicas, a due watch is **claimed** with one atomic update, so exactly one replica
  runs it.
* A failed run (refused key, rate limit, engine down) is recorded with its reason and tried again
  at the next scheduled time. It never becomes the baseline, so the first *successful* run does.

## Access

Analysts create, run and remove watches; viewers see them; other teams never do. Every change and
every alert is in the audit log. The watched query and known servers are encrypted at rest.

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `ARGUS_FINGERPRINT_WATCH_ENABLED` | `true` | Run the watch loop (also needs `ARGUS_MONITORS_ENABLED`) |
| `ARGUS_SHODAN_API_KEY` / `ARGUS_CENSYS_API_TOKEN` | — | Which engines can be watched |

## API

```http
POST /api/fingerprint-watches
{"investigation_id": "inv_…", "entity_id": "favicon_…", "engine": "shodan", "interval_hours": 24, "severity": "high"}

GET    /api/fingerprint-watches
POST   /api/fingerprint-watches/{id}/run
DELETE /api/fingerprint-watches/{id}
```

```python
client.watch_fingerprint(inv_id, entity_id, engine="censys", interval_hours=168)
```
