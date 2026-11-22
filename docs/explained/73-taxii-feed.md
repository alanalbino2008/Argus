# 73 — A TAXII 2.1 threat-intelligence feed

## Why

Security teams run a threat-intelligence platform (OpenCTI, MISP) or a SIEM (Microsoft Sentinel,
Splunk) that blocks, alerts and hunts on indicators. What Argus learns (*this domain is C2*, *these
lookalikes imitate us*, *these servers share the attacker's favicon*) should reach those tools
without anyone copying and pasting. **TAXII** is the standard way they pull indicators: point them
at a TAXII server and they fetch new STIX objects on their own schedule.

## What Argus serves

A read-only TAXII 2.1 server. Discovery is at `/taxii2/`; **each workspace is its own API root**,
`/taxii2/{workspace}/` (its id or slug). Three collections, all STIX 2.1 indicators marked TLP:AMBER
and attributed to the Argus identity:

| Collection | What | Indicator |
| --- | --- | --- |
| **Tagged entities** | Every domain, IP address, email address and URL the team tagged | Tags → `labels`; note → `description` |
| **Lookalike domains** | Lookalikes found by brand watches | `lookalike-domain`, the technique, `brand:acme.com`; high severity → `malicious-activity` |
| **Fingerprint-watch servers** | Servers sharing a watched favicon, JARM, HASSH or certificate | Address and port; the fingerprint and its search in the description |

A fourth collection, **Campaigns** (Phase 77), carries a STIX `campaign` per group of the indicators
above that share infrastructure, with an `indicates` relationship from each member's indicator (the
same ids as in the other collections) and the indicators themselves.

People, organisations and other non-observables are never exported: only what a security tool can
match on.

## Incremental pulls

* Indicator **ids are deterministic**: the same domain keeps the same id across pulls, so platforms
  update it rather than create a duplicate. Editing a tag changes its `modified` time.
* `date_added` is **when Argus first knew it**. A client that remembers the last
  `X-TAXII-Date-Added-Last` and asks `added_after` that time gets only what is new.
* Paging (`limit`, up to 1,000, and `next`), `match[id]`, `match[type]`, `/manifest/` and
  `/objects/{id}/` follow the specification. Tested with the OASIS reference client,
  `taxii2-client`.

## Connecting a client

1. In Argus, **Settings → API keys**: create a **viewer** key in the workspace to share (a key bound
   to one workspace can only ever read that workspace).
2. In the TAXII client: server `https://argus.example/taxii2/`, version 2.1, user name anything,
   password the key. Clients that support a Bearer token can use that instead.
3. Choose the collections to pull.

Settings → API & integrations shows the discovery URL and the workspace's API root. Every pull is in
the audit log (`taxii.read`).

## Access

HTTP Basic is accepted *only* with an API key as the password, never an account password. Other
workspaces' roots are invisible (they answer 404). The server is read-only: there is nothing to
write to.
