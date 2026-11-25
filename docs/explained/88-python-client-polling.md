# 88. The Python client: cheap polling, TAXII and watch health

Scripts and SIEM connectors poll Argus: every few minutes they ask for campaigns or new indicators.
Phase 85 lets the server answer `304 Not Modified` when nothing changed; this phase makes the
official Python client use it, and covers what phases 84 to 87 added.

## Conditional requests, for free

Every `GET` answer that carries an `ETag` is remembered (up to 256, least recently used first),
keyed by workspace, path, query and `Accept`. The next identical request sends `If-None-Match`; a
`304` returns a copy of the remembered answer. Nothing changes for the caller except speed, and
`argus.not_modified` counts the answers saved. Clients made with `in_workspace()` share the memory
safely, since the workspace is part of the key.

## TAXII

* `taxii_root()`: the workspace's API root (from the client's workspace, or the server's default);
* `taxii_collections()`;
* `taxii_objects(collection, added_after=None, page_size=500)`: every STIX object, oldest first,
  following `next` across pages. Keep the newest `date_added` you have read and pass it next time to
  read only what is new.

## Watches

* `watch_health()`: brand and fingerprint watches that are failing or that Argus paused (Phase 87),
  paused ones first, with the failure count, since when, and the last error;
* `run_watch(kind, id)`: run a watch now, which also resumes a paused one;
* `delete_watch(kind, id)`.
