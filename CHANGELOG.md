# Changelog

## [1.2.0] — Phase 2: Persistence, history & live replay

### Added
- `argus/storage/`: SQLAlchemy 2.0 async persistence (SQLite default, PostgreSQL-ready) with a
  repository layer, portable upserts, and SQLite WAL mode.
- Write-behind `InvestigationRecorder`: batched checkpoints every second plus a final snapshot.
- Crash recovery: investigations left running by a restart are marked failed on startup.
- `argus/core/settings.py`: `ARGUS_*` environment configuration via pydantic-settings.
- API: `GET /api/health`, `DELETE /api/investigation/{id}`, `GET /api/entities/search`
  (cross-investigation pivot), filtering and pagination on `GET /api/investigations`.
- WebSocket snapshot replay: late joiners and historical investigations receive all findings so far.
- Web UI: History tab (open, filter, delete), "Seen in other investigations" pivot, `?inv=` deep links.
- Docker: named data volume, `HEALTHCHECK` on `/api/health`.
- Tests: persistence, recorder checkpointing, crash recovery, replay and search (45 → 55).
- Docs: `docs/explained/02-persistence-and-history.md`.

### Changed
- Per-client bounded WebSocket send queues: slow browsers no longer stall the engine (backpressure).
- Running scans are dropped from memory once persisted; the database is the source of truth.
- Cytoscape.js is vendored (`argus/web/vendor/`) instead of loaded from a CDN — works offline and
  enables a strict Content-Security-Policy.

### Security
- Fixed stored XSS: the live activity feed rendered attacker-controlled entity labels (e.g. DNS TXT
  records) via `innerHTML` without escaping. Verified with a Playwright regression test.

## [1.1.1] — Module failure reporting

### Fixed
- Modules swallowed per-source errors, so total failures looked like empty results and never
  tripped the circuit breaker. Runs are now classified success / degraded / failed.
- DNS timeouts were recorded as "no valid MX records", inflating risk scores; now "unknown".

## [1.1.0] — Phase 1: Engine hardening

### Added
- `argus/core/http.py`: shared resilient HTTP client — retries with exponential backoff and
  full jitter, `Retry-After` support, per-host rate limiting and concurrency caps, telemetry.
- Engine worker pool for parallel recursive enrichment.
- Per-module timeouts, circuit breaker, `max_entities` cap, cooperative cancellation.
- `CANCELLED` status, `scan_cancelled` event, per-module and HTTP statistics on investigations.
- `POST /api/investigation/{id}/cancel` endpoint; richer investigation status payload.
- Proxy support (`HTTP(S)_PROXY`) via `trust_env`.
- Test suites for engine, HTTP client and API (14 → 40 tests); CI on all branches.
- Plain-English explainer: `docs/explained/01-engine-and-reliability.md`.

### Changed
- API uses the FastAPI lifespan handler (replaces deprecated `on_event`), keeps strong references
  to background scan tasks, logs failures, and cancels scans cleanly on shutdown.
- API validates input (depth/concurrency bounds, blank targets, unknown modules → HTTP 422).
- Web UI reacts to failed/cancelled scans and surfaces module errors in the live feed.

### Fixed
- Engine processed entities strictly one at a time; `concurrency_limit` and `rate_limit_delay`
  were largely unused.
- Crashed background scans stayed `running` forever and their exceptions were lost.
