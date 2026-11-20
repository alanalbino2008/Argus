# 67 — Censys searches from Argus, on the Censys Platform

## Two things in this phase

1. **Fix.** Argus's copyable Censys searches used Censys's retired *Search 2.0* syntax
   (`services.jarm.fingerprint: …`). They now use the **Censys Query Language (CenQL)** of the
   Censys Platform.
2. **Feature.** As with Shodan (phase 63), an analyst can run the search from Argus: *How common?*
   and *List hosts*, with *Investigate* for each host found.

## The searches (`argus/intel/cenql.py`)

All are exact matches (`field = "value"`, which CenQL documents as a case-sensitive exact match)
on hosts:

| Fingerprint | CenQL | Where the field name is documented |
|---|---|---|
| Certificate (SHA-256) | `host.services.cert.fingerprint_sha256 = "…"` | CenQL docs (the `sha256` alias table) |
| Favicon (SHA-256) | `host.services.endpoints.http.favicons.hash_sha256 = "…"` | CenQL docs (the `sha256` alias table) |
| JARM | `host.services.jarm.fingerprint = "…"` | Platform API data schema (`Service.jarm.fingerprint`) |
| SSH HASSH | `host.services.ssh.hassh_fingerprint = "…"` | Platform API data schema (`Service.ssh.hassh_fingerprint`) |

Favicons now match on **SHA-256** rather than MD5, because that is the hash Censys's CenQL
documentation lists. Argus already records it. Every Censys field name lives in that one module,
so a future rename is a one-line change.

## Running them from Argus

Configure a **Censys Platform personal access token** (the account needs Censys's *API Access*
role):

| Setting | |
|---|---|
| `ARGUS_CENSYS_API_TOKEN` | The token, sent as `Authorization: Bearer` |
| `ARGUS_CENSYS_ORGANIZATION_ID` | Optional: the organisation whose credits are used (otherwise the token's free wallet) |

| Button | Censys call | What you get |
|---|---|---|
| **How common?** | two `POST /v3/global/search/aggregate` calls (by autonomous-system name, by country, 5 buckets each) | total matching hosts, top organisations and countries, and the rarity verdict (unique / rare / uncommon / common) |
| **List hosts** | `POST /v3/global/search/query`, `page_size` 100, only the fields shown | IP and matched port, transport, DNS names, network operator and ASN, country and city, protocol |

Certificate and web-property hits are skipped: the list is of servers, which are what can be
investigated.

**Credits.** Censys's documentation does not say whether searches or aggregates use credits, so
the buttons say they use the plan's credits *where it charges*. They never claim to be free.
Shodan's count stays labelled free, because Shodan documents its count endpoint as free.

## Safety, as for Shodan

- Only on an analyst's click (analyst role), rate-limited to 10 a minute per key, and audited
  with the engine, the mode, the entity type and the number of results.
- The search is the entity's own, never free text.
- The token never reaches the browser, an error message or a log line.
- Results are shown, not merged into the scan's record.
- Clear errors for each case:
  - a refused token (401);
  - an account without the API Access role, plan or credits (403);
  - a query Censys no longer accepts (400/422), which would mean CenQL changed;
  - rate-limiting (429);
  - an outage.

Tests: `tests/test_internet_search.py` (requests, parsing, errors and the API end to end, with Censys
faked).
