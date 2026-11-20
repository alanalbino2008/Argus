# 61 — Saved queries, hunts and query alerts

Phase 59 made the graph something you can ask questions. This phase makes those questions last:
saved, shared, asked of every investigation at once, and asked again automatically after
every scan.

## Saved queries

A saved query is a name, an AQL query, an optional description, and two alert settings. They
belong to the workspace, so the whole team sees and uses them. The name, query and description
are stored in one encrypted column, because queries often contain an email address, a person's
name or a client's domain.

From the graph's **Query** tab: run a query, press **Save**, give it a name, and choose whether it
should alert, and at what severity. Each saved query offers **Run** (on the open investigation),
**Hunt** (on all of them), **Alert/Mute** and delete.

## Hunts

```text
POST /api/hunt  {"query": "category:favicon degree>=2", "investigations": 50}
```

A hunt runs one query over the workspace's most recent investigations: completed ones by
default, plus running ones with `include_running`. Each investigation's graph is loaded and
queried in a worker thread. The answer lists, for every investigation that matches, its target,
date, match count and the first five matches:

> **2** of 40 investigations match · 6 matches · 180 ms

Typical hunts:

| Question | Query |
|---|---|
| Where have we seen this favicon? | `category:favicon mmh3:-568180311` |
| Every exploited CVE across clients | `type:vulnerability intel.kev:*` |
| Exposed databases | `type:port value~"(6379\|27017\|9200\|5432)"` |
| A person across cases | `"dana whitfield"` |

**Limits**: at most 200 investigations per hunt, a 25-second budget (the result says `partial` if
the oldest weren't reached), and 20 hunts a minute per key. Every hunt is written to the audit
log with how many investigations it searched and matched.

## Query alerts

When any scan in the workspace **completes**, Argus runs every alerting saved query on its graph
(`argus/intel/hunt.py → check_after_scan`):

1. It finds the previous completed scan of the same target.
2. It runs the query on both graphs, collecting **every** matching entity: `| limit` and
   `| count` shape what people see, never the comparison.
3. Entity IDs are a hash of type and value, so the same host has the same ID in both scans and
   "new" is an exact set difference.
4. If anything is new, it raises an alert with the query's severity, for example
   *Saved query "Exploited CVEs": 1 new match on acme-corp.example*. A summary names up to ten of
   the new matches.

The first scan of a target has nothing to compare with, so any match is new. Failed and cancelled
scans are skipped. A saved query that no longer parses is skipped and logged, without affecting
the others.

Alerts use the same table and transactional outbox as monitoring alerts, so every configured
channel delivers them: email, signed webhooks, Slack, Teams, Jira, ServiceNow, Splunk and
Sentinel. Webhook payloads gain `alert.saved_query`:

```json
{"id": "sq_…", "name": "Exploited CVEs", "query": "type:vulnerability intel.kev:*",
 "new_count": 1, "total_count": 3, "new_matches": ["CVE-2099-0001"]}
```

Each saved query records when it was last checked, when it last alerted, and how many alerts it
has raised.

## Recipes

- **Watch your estate for regressions**: *Exploited CVEs*
  (`type:vulnerability intel.kev:*`, high), combined with a monitor that re-scans daily.
- **Shadow IT**: `type:subdomain -sources:subdomain_finder` alerts on hosts only passive DNS or
  the archive knew about.
- **Brand protection**: `type:domain lookalike:*` alerts on newly registered impostor domains.
- **Shared infrastructure**: `category:favicon degree>=2` alerts when a new host starts serving an
  icon you've seen before.

## Security

- Saved queries are scoped to their workspace: another team's key gets 404 on every route, and its
  hunts never see your investigations.
- Creating, changing and deleting saved queries needs the analyst role. Listing and hunting are
  reads (viewer).
- Every change, hunt and alert is audited.

Tests: `tests/test_saved_queries.py`.
