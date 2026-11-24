# 85. Caching campaigns and TAXII collections

Campaigns are computed from every lookalike, watched server and tagged entity of a workspace, and
TAXII collections are built from the same data. A SIEM or threat-intel platform polls TAXII every few
minutes, and analysts reopen Monitoring all day, while that data changes only when a watch runs or
someone tags an entity. Recomputing it on every request wasted CPU and database reads.

## The data version

Each workspace has a counter in the `data_versions` table (migration 0034). Every write that changes
what campaigns or TAXII serve raises it, **in the same transaction as the write**:

* brand watches: created, changed, deleted, each run (new lookalikes, new triage), each takedown step;
* fingerprint watches: created, deleted, each run;
* annotations (tags and notes): set or removed.

Reading it is one primary-key lookup. Because it is in the database, a write on one replica is seen
by every replica straight away; nothing has to be invalidated by hand.

## What uses it

* **An in-memory cache.** Campaigns, and each TAXII collection's objects, are kept per workspace
  under the version they were computed at, and reused until the version moves. The cache is per
  process, bounded (128 entries, least recently used first) and starts empty after a restart.
* **ETags.** `GET /api/campaigns` and the TAXII `objects/`, `objects/{id}/` and `manifest/` endpoints
  answer with a weak `ETag` derived from the version, the Argus release, the path and the query
  (so each page and filter has its own), and with `Cache-Control: private, no-cache`. A client that
  sends `If-None-Match` with it gets `304 Not Modified` with no body, after one lookup, while nothing
  changed. A 304 does not count against the per-minute limits of Phase 83; TAXII 304s are still
  audited (`taxii.read` with `not_modified`).

`argus_derived_cache_total{cache, result}` counts hits, misses and 304s.

## Notes

* Campaign *membership* only changes through the writes above. The brand-protection summary is not
  cached as a whole: its period is relative to now, but the campaigns inside it are.
* Restoring the database from a backup can bring an earlier version number back with different
  data; restart Argus after a restore (which an operator does anyway) so its caches start empty.
