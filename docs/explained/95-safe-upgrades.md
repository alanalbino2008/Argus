# 95. Safe upgrades

Upgrading Argus can change the database schema (a *migration*). In 1.91.0 a migration rebuilt the
`cases` table on SQLite in a way that also deleted every case's items (fixed in 1.93.1). That
should never be possible again, whatever a future migration does wrong.

## What happens at an upgrade (SQLite)

When the database is behind the new version and holds data:

1. **A copy first.** The database is copied with SQLite's `VACUUM INTO` to `pre-upgrade/` next to
   it (for example `pre-upgrade/argus-0040-to-0041-20261125-191500.db`). The copy is checked with
   `PRAGMA integrity_check` and is readable by its owner only. The newest three are kept.
2. **The migration** runs with foreign keys off, so rebuilding a table cannot cascade to its children
   (1.93.1), and they are checked afterwards.
3. **Nothing may go missing.** Every table is counted before and after. If any table has fewer rows
   (short-lived tables such as sign-in states and rate-limit counters aside), the copy is put back,
   and Argus stops with an error naming each table and its row counts. It does not start on a damaged
   database.
4. If the migration itself fails, the copy is put back too.

An up-to-date database, or a new empty one, is not copied.

## Putting a copy back by hand

Stop Argus, then replace the database file with the copy (and delete any `-wal` and `-shm` files
next to it). The copy is an ordinary SQLite database, encrypted where the live one is, and needs the
same encryption key.

## PostgreSQL

PostgreSQL migrations run in one transaction, so a failing migration leaves nothing half-done, and
`ALTER TABLE` does not rebuild tables. Take a `pg_dump` (or a snapshot of the volume) before
upgrading, as for any database upgrade; the Helm chart's upgrade notes say so.
