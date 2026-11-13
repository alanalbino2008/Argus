# Changelog

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
