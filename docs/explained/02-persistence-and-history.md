# 02 — Persistence, History & Live Replay (Plain-English Guide)

> Purpose: explain how Argus remembers investigations, and why each design choice was made.

## 1. The problem

Before Phase 2 every investigation lived only in RAM. Restart the server → everything gone.
Memory grew forever, and if you opened the web page after a scan started you missed
everything found before you arrived.

## 2. The database layer (`argus/storage/`)

| File | Job | Analogy |
|---|---|---|
| `db.py` | Defines the three tables and opens the connection | The filing cabinet |
| `repository.py` | The *only* code that writes SQL | The librarian: you ask for a book, you don't search the shelves yourself |
| `recorder.py` | Saves a running scan to the database in the background | A court stenographer |
| `core/settings.py` | Reads configuration from environment variables | The settings menu |

### The tables
* **investigations** – one row per scan (target, status, timings, stats, risk score).
* **entities** – every node found, tagged with which investigation it belongs to.
* **relations** – every edge.

Each row stores a few **indexed columns** we search on (status, target, entity type/value)
**plus the full record as JSON**. Indexes make searching fast; the JSON copy means adding
a new field to a model never requires changing the database structure.

> **Interview line:** "I used the Repository pattern — the API never builds SQL itself, so
> moving from SQLite to PostgreSQL is a one-line configuration change
> (`ARGUS_DATABASE_URL`), not a code change."

### Why SQLite by default, PostgreSQL for production?
SQLite is a single file — zero setup, perfect for one analyst. PostgreSQL handles many
users writing at once. SQLAlchemy 2.0 (async) speaks both. SQLite runs in **WAL mode**
(write-ahead logging) so the web UI can read while a scan is writing. *(PostgreSQL support
is built in via the `postgres` extra but has not yet been exercised in CI.)*

## 3. Write-behind recording — saving without slowing down

Writing each discovery to disk the instant it's found would make the scan wait on the disk
thousands of times. Instead the **recorder**:

1. listens to the event bus and collects new findings in memory,
2. every second, saves the batch in **one transaction** (a *checkpoint*),
3. when the scan ends, saves a complete final snapshot.

So a crash loses at most ~1 second of findings, and a database hiccup is retried on the next
checkpoint instead of killing the scan.

### Crash recovery
If the server dies mid-scan, that investigation is stuck as "running" forever. On startup
Argus finds those rows and marks them **failed – "Interrupted: server stopped before the scan
finished"**, keeping the partial results.

## 4. Live replay over WebSockets

When the browser connects to `/ws/stream/{id}` the server first sends a **snapshot** —
everything found so far — then streams live events. So:

* open the page mid-scan → you see everything, not just what's found after you arrived;
* open an old investigation from **History** → same code path, it just never gets live events.

**Race-condition detail worth mentioning:** the snapshot is built and the client is registered
for live events with *no `await` in between*. In asyncio, code only switches tasks at an
`await`, so no event can sneak through the gap and get lost.

### Slow clients can't slow the engine
Previously the engine waited for every browser to receive each message. Now each browser gets
its **own queue** with a dedicated sender task. The engine just drops messages into queues and
moves on. A client that falls 2,000 messages behind is disconnected rather than allowed to
use unlimited memory (this is called **backpressure**).

## 5. New features you can demo

* **History tab** – every past investigation with status and risk score; click to reopen,
  ✕ to delete. Filter by target.
* **Deep links** – `http://localhost:8000/?inv=<id>` opens a saved investigation directly.
* **"Seen in other investigations"** – click any node and the inspector shows every *other*
  investigation containing the same IP/email/domain. This is real analyst tradecraft:
  correlating infrastructure across cases.
* **`GET /api/health`** – used by Docker's `HEALTHCHECK` to restart an unhealthy container.

## 6. The security bug found along the way (great interview story)

The live activity feed inserted entity labels into the page with `innerHTML` **without
escaping**. Entity labels come from the *target* — DNS TXT records, HTTP headers, GitHub
profile names — which the target fully controls. A hostile target could publish
`<img src=x onerror=...>` in a TXT record and run JavaScript **in the analyst's browser**:
a stored XSS against the investigator.

* **Proven:** a Playwright browser test injected the payload — the old code executed it,
  the fixed code renders it as harmless text.
* **Fix:** escape all OSINT data before rendering; `escapeHtml` now also escapes `'`.
* **Defence in depth:** Cytoscape is now served locally instead of from a CDN, which lets
  Phase 3 add a strict Content-Security-Policy (`script-src 'self'`).

> **Interview line:** "OSINT tools ingest attacker-controlled data by design, so the
> analyst's own tooling is attack surface. I found and fixed a stored XSS in Argus's live
> feed and verified the fix with a browser-level regression test."

## 7. Questions you might be asked

* **"Why not save everything at the end?"** A crash would lose the whole scan; checkpoints bound the loss to ~1s.
* **"What's an upsert?"** Insert-or-update in one statement (`ON CONFLICT DO UPDATE`), so saving the same entity twice merges instead of duplicating.
* **"How do you migrate the schema later?"** Phase 4 adds Alembic migrations; the JSON-document design already minimises how often that's needed.
