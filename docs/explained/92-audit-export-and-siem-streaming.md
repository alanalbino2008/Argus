# 92. Audit log export and streaming to a SIEM

Argus's audit log is tamper-evident: each entry carries the hash of the one before (Phase 3). But an
auditor wants it as a file they can check without Argus, and a security team wants it in the SIEM it
already watches, ideally before anyone who breaks in can touch it.

## Exports you can check offline

Settings → Audit log → **Export (signed)**, or `GET /api/audit/export` (admin; filters `since`,
`until`, `action`, `actor_id`; platform administrators can add `scope=all`). The file is JSON Lines:

* one entry per line, with its `id`, `prev_hash` and `hash`;
* a last line, the **manifest**: the SHA-256 of the lines above, the number of entries, the filters,
  who exported it and when, the chain's head at that moment, and an **Ed25519 signature** by this
  server's report-signing key (the public half is at `/api/report-signing-key`).

Check it anywhere Argus is installed:

```bash
argus --verify-audit argus-audit.jsonl --report-key <public key>
```

It checks that every entry's hash matches its content, that consecutive entries link to each other,
that the lines match the manifest, and that the manifest is signed (by that key, if given). A
workspace's export skips other workspaces' entries: the gaps are reported, not errors. A platform
export with no filter is one unbroken stretch of the chain.

**CSV** is offered for spreadsheets. It is not signed, and cells that a spreadsheet would read as a
formula (`=`, `+`, `-`, `@`) are prefixed with `'`.

Exports are audited (`audit.export`) and limited to 10 a minute.

## Streaming to a SIEM

Settings → Audit log → **Streaming to a SIEM** (or `POST /api/audit/streams`): choose one of the
workspace's Splunk, Sentinel or webhook destinations (Monitoring → Notifications), and start from now
or from the beginning.

* Every 30 seconds, one replica sends new entries **in order**. Each is a notification event of type
  `audit.event` with id `audit-<entry id>`, carrying the entry and its chain hashes. Webhooks are
  signed like every other delivery.
* A **checkpoint** moves only when the destination accepts an entry. If the SIEM is down, entries
  wait; when it is back, the stream catches up. Nothing is skipped.
* A platform administrator can stream every workspace's entries, sign-ins and platform events included.
* `argus_audit_stream_events_total{outcome}` and `argus_audit_stream_lag_entries` show progress;
  the `ArgusAuditStreamFailing` alert fires when every attempt has failed for 30 minutes.

Stopping the SIEM feed is what an intruder would do first, so pausing or removing a stream can be
put under two-person approval (`audit.stream_stop`, Phase 90).

Python client: `audit_export()`, `audit_streams()`, `stream_audit()`.
