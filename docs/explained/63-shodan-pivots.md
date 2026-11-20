# 63 — Shodan pivots on demand

Phases 60 and 62 turned favicons, TLS and SSH configurations, and certificates into fingerprint
nodes, each with the search that finds every other server sharing it. This phase lets an analyst
run that search from Argus.

## The question that matters first: how common is it?

A shared fingerprint is only as meaningful as it is rare:

| Servers sharing it | Verdict | What it tells you |
|---|---|---|
| 1 | **unique** | The fingerprint identifies this one server |
| 2–50 | **rare** | A small cluster: a strong lead to the same operator, kit or estate |
| 51–5,000 | **uncommon** | A lead worth narrowing down (by organisation, country) |
| more | **common** | A default configuration: says little about who runs it |

**How common? (free)** answers it with Shodan's count endpoint, which spends no query credits. It
also lists the top five organisations and countries among those servers. A rare JARM that
mostly sits at one small hosting company is a very different finding from a JARM spread across a
big CDN.

## Listing the servers

**List hosts (1 credit)** returns up to 100 matching servers: IP and port, host names,
organisation, country, product and version, and when Shodan last saw them. Each has
**Investigate**, which opens the new-investigation form with the IP filled in. These are
*third parties' servers*, so the form still asks for the purpose and authorisation like any
other scan.

## Design choices

- **On demand only.** Searches cost money and reach a third party, so Argus never runs them by
  itself.
- **The node's own search.** The endpoint takes an entity ID and runs the search stored on that
  entity (`search_queries.shodan`), never free text. It is a pivot feature, not a general Shodan
  proxy.
- **The key stays on the server.** It is read from `ARGUS_SHODAN_API_KEY`, registered for
  redaction so it can't appear in an error or a log line, and never sent to the browser. The
  browser only learns *whether* a key exists.
- **Audited and limited.** Each lookup is written to the audit log (investigation, mode, entity
  type, number of results) and limited to 10 a minute per key.
- **The scan record stays honest.** Results are shown, not merged into the investigation. An
  investigation remains what its scan observed, which is what monitoring, diffs and saved-query
  alerts compare.
- **Clear failures.** A refused key, a plan without the needed filter, rate-limiting and outages
  each get their own message.

## API

```bash
curl -X POST "$ARGUS/api/investigation/$ID/internet-search" -H "Authorization: Bearer $KEY" \
     -H 'Content-Type: application/json' -d '{"entity_id": "generic_3f2a…", "mode": "count"}'
```

```json
{"engine": "shodan", "mode": "count", "total": 12,
 "rarity": {"level": "rare", "meaning": "A small cluster: a strong lead to the same operator or kit."},
 "top_orgs": [{"value": "Bad Hosting Ltd", "count": 9}], "top_countries": [{"value": "NL", "count": 7}],
 "hosts": []}
```

Analyst role. `GET /api/internet-search` says whether Shodan is configured.

Tests: `tests/test_internet_search.py`.
