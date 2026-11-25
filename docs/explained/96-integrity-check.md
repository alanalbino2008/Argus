# 96. Integrity check

Damage is quietest when nobody looks. A failing disk, a faulty upgrade (1.91.0 deleted case items
on SQLite), or someone editing the database by hand can each leave data broken. The integrity check
looks, and says what it found.

## What it checks

| Check | How |
| --- | --- |
| **Storage** | SQLite's `PRAGMA integrity_check` (PostgreSQL verifies its own pages with data checksums) |
| **References** | For every foreign key in the schema, rows pointing at a parent that no longer exists, such as case items without their case |
| **Audit chain** | The whole hash chain recomputed: any edited or removed entry is named |
| **Evidence** | Every captured file against its recorded SHA-256, every manifest against its digest, every chain of custody |

It only reads: nothing is changed or repaired. With the case vault locked, the encrypted parts (audit
details, evidence) cannot be read; those checks are reported as **skipped**, not as damage.

## Running it

* Every week, automatically (one replica at a time).
* Settings → **Integrity** → **Check now** (platform administrators; at most twice in ten minutes),
  or `POST /api/integrity/check`. `GET /api/integrity` returns the last result.
* `argus --check` on the server, which exits with 1 when something is wrong (useful in a cron job or
  before an upgrade).

Every run is audited (`integrity.check`, outcome `failure` when anything was found).
`argus_integrity_problems` holds the number of problems found, and the `ArgusIntegrityProblems`
alert (critical) fires as soon as it is above zero.

## When it finds something

Do not delete anything. Compare with the latest backup (Phase 56) and the pre-upgrade copies
(Phase 95), and restore from the newest one that checks whole.
