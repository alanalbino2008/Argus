# Changelog

## [1.9.0] — Phase 9: People & software intelligence

### Added
- `profile_enricher` module: when an account is found, reads the platform's official public API
  (GitLab, Reddit, Hacker News, Keybase, Dev.to, Mastodon, Docker Hub, Bluesky) for the owner's
  display name, bio, location, employer, website, join date and linked accounts; Keybase proofs and
  Mastodon `rel="me"` links are recorded as **verified** and their handles are hunted in turn.
  `github_hunter` now records the GitHub profile itself with the same facts.
- New `LOCATION` entity type (ATT&CK T1591.001 *Determine Physical Locations*; STIX `location`).
- `software_intel` module: software end-of-life status (endoflife.date) for banners such as
  `PHP/7.4.3`, and CVE threat intelligence — CISA KEV (exploited in the wild, ransomware use),
  FIRST EPSS exploit probability, NVD CVSS score and description.
- Enrichment modules: the engine runs them on entities at the depth limit, so leaf CVEs and profiles
  are still enriched, without expanding the scan further.
- Identity resolution (`argus/intel/identity.py`) and `GET /api/investigation/{id}/people`: linked
  identifiers grouped into personas with a dossier — accounts and profile facts, emails, handles,
  locations, employer, websites, breaches, a timeline, exposures and related attack paths. Links are
  graded verified / strong / possible. Access is recorded in the audit log.
- Attack paths: new `end_of_life_software` rule (10 rules); `exploitable_public_service` uses KEV,
  ransomware and EPSS to raise likelihood and explain *why* a CVE is urgent.
- Risk analyser flags actively exploited CVEs first, and end-of-life software.
- Web: **People** page (persona cards → dossier with accounts, timeline, exposure and *Show on graph*,
  shortcut `U`); graph panel shows profile facts, support status and CVE intelligence.
- Demo: verified persona with Keybase/GitHub/Mastodon profiles, real KEV/EPSS/CVSS data for its
  FortiOS CVEs and an end-of-life PHP release.
- `docs/explained/09-people-and-software-intelligence.md`.

### Changed
- Shared inboxes (`info@`, `security@`, …) are no longer turned into usernames and hunted across
  social networks: they are not people, and the results were strangers' accounts.
- Remote avatars are never loaded in the UI (initials instead), so viewing a dossier doesn't reveal
  the analyst's IP address to the subject's platforms.

### Fixed
- README claimed 60+ username platforms; the hunter checks 35.
- Duplicate links on profiles (the same URL in a link's address and its text) are de-duplicated.

## [1.8.0] — Phase 8: Interface redesign

### Added
- Redesigned web interface: left navigation with dedicated Overview, Graph, Attack Paths, Monitoring,
  History and Settings pages; welcome page with "Try the demo"; single New-investigation dialog with
  live type detection, depth slider, rules of engagement and "Keep watching".
- Overview dashboard: risk gauge, attack paths by severity, asset breakdown, exposure flags, exports.
- Graph: icons per entity type, size by importance, constant-size labels with importance-based
  visibility, hover focus, label-aware layouts, filterable legend, search; side panel linking each
  entity to its neighbours, attack paths and other investigations.
- Settings page: API-key management, audit log with one-click integrity verification, plugin status.
- Light and dark themes (system-aware, no flash), toasts, progress bar and Stop button, first-run
  tour, tooltips, keyboard shortcuts, phone layout.
- `docs/explained/08-interface-design.md`.

### Changed
- Front end rewritten as ES modules; all HTML built with an auto-escaping template (XSS-safe by
  construction). Still no inline scripts under the strict CSP.
- The three novelty themes are replaced by Light / Dark / System.

## [1.7.0] — Phase 7: Continuous monitoring & drift detection

### Added
- Drift detection (`argus/intel/diff.py`): compare two scans of a target — assets added/removed,
  security-relevant fact changes, attack paths new/escalated/reduced/resolved, risk trend and a
  one-line headline. `GET /api/investigation/{id}/diff[?against=]`.
- Monitors: scheduled re-scans (`/api/monitors`) under the same rules of engagement and scope checks
  as manual scans; the scheduler re-validates scope before each run, respects the concurrent-scan
  cap and is fully audited.
- Alerts on material drift (`/api/alerts`, acknowledge); unread badge on the History tab.
- UI: Alerts and Monitors panels, Compare and Watch on every investigation, "What changed" view, new
  assets highlighted on the graph.
- Demo now includes an earlier snapshot so drift can be explored offline.
- Alembic migration 0002 (`monitors`, `alerts`); `docs/explained/07-continuous-monitoring.md`;
  tests 196 → 204.

### Changed
- Attack-path identity is now rule + subject, so a worsening scenario is reported as escalated rather
  than as one path resolved and another opened.
- Manual and scheduled scans share a single launch function.

## [1.6.0] — Phase 6: Attack Path Engine

### Added
- **Attack Path Engine** (`argus/intel/paths.py`): nine explainable rules chain findings into ranked
  attack scenarios (credential exposure, spoofable email domain, exploitable public service, exposed
  sensitive service, identity correlation, TLS interception, subdomain takeover candidate, malicious
  reputation, web information leak), each with a risk score, the ATT&CK route from Reconnaissance to
  Initial/Credential Access, narrative, evidence and remediation. `GET /api/investigation/{id}/paths`.
- **Attack Paths tab**: severity-coloured cards, entity chain, ATT&CK route; "Show on graph"
  highlights the whole path and fades everything else. Paths also appear in the executive report.
- **Built-in demo investigation** (`argus --load-demo`, `POST /api/demo`): a fictional company using
  only reserved `.example` domains and TEST-NET IPs that exercises every rule.
- DNS module records explicit three-valued facts on domains (`dns_checked`, `dmarc_policy`,
  `spf`: present / missing / unknown) so reasoning never treats a failed lookup as a missing control.
- `docs/explained/06-attack-path-engine.md`; tests 178 → 196.

### Fixed
- Executive report claimed all collection was passive; it now states that the TLS and HTTP modules
  contact the target and that attack paths are assessments, not confirmed exploitation.

## [1.5.0] — Phase 5: Intelligence features

### Added
- MITRE ATT&CK mapping (Reconnaissance, TA0043): findings classified by technique with defensive
  guidance; every module declares the techniques it emulates and whether it is active or passive;
  ATT&CK Navigator layer export; ATT&CK panel in the web UI.
- STIX 2.1 export: observables with deterministic IDs, identities, CVE vulnerabilities, attack
  patterns and relationships in a TLP:AMBER report; strictly validated with the `stix2` library.
- Optional API-key modules: VirusTotal reputation, Have I Been Pwned breaches (new `breach` entity,
  T1589.001) and the Shodan host API (products and versions per port). They load only when their
  key is configured and respect each service's quota via per-host rate limits.
- Secret redaction: API keys are scrubbed from every recorded error and log message Argus stores.
- Plugin system via the `argus.modules` entry-point group: allowlist-only (`ARGUS_PLUGINS`),
  validated (no shadowing built-ins, real ATT&CK IDs only), failure-isolated, audited at startup;
  `GET /api/plugins`.
- `docs/explained/05-intelligence-features.md`; tests 147 → 178.

### Changed
- `/api/modules` reports ATT&CK techniques, active/passive, required settings, configuration
  status and origin (built-in or plugin).

## [1.4.0] — Phase 4: Engineering quality & delivery

### Added
- CI pipeline: ruff (incl. bandit security rules) + format check, mypy, pytest on Python 3.10–3.13
  with an 85 % coverage gate, clean-virtualenv package install test, pip-audit, Docker build with
  health and image-content checks.
- CodeQL security scanning (Python and JavaScript), Dependabot (pip, Actions, Docker).
- Tag-driven release workflow: version check, tests, GitHub Release with changelog notes, image
  published to `ghcr.io`.
- Alembic migrations, applied automatically at startup; pre-migration databases are adopted; a test
  fails if models and migrations drift.
- Offline parsing tests for every collector (fake HTTP session + real dnspython records) and CLI tests;
  coverage 68 % → 87 %.
- `.pre-commit-config.yaml`, `CONTRIBUTING.md`, `docs/explained/04-engineering-quality.md`.
- `requirements-dev.txt` pins ruff, mypy and other tooling so local, pre-commit and CI results match.

### Changed
- Version is single-sourced from `argus/__init__.py` (package metadata, API, User-Agent).
- Docker image rebuilt as a wheel-only multi-stage image on Python 3.12 with OCI labels and a data volume.
- Certificates are keyed by SHA-256 fingerprint; the analyzer flags expired, self-signed and
  soon-to-expire certificates.

### Fixed
- TLS analyzer extracted nothing (no SANs, issuer or dates) because `getpeercert()` returns `{}` for
  unverified certificates; certificates are now parsed from DER with `cryptography`.
- `alembic` was used but not declared as a dependency (installed packages crashed on start).
- No `.dockerignore`: `.env`, local databases and `.git` could be copied into images.
- Shodan module could send private IPs to its API (relied on a flag set by a concurrent module).
- GitHub blog URLs with paths produced invalid domain entities.
- Runtime `assert` (removed under `python -O`) replaced with an exception.

## [1.3.0] — Phase 3: Platform security

### Added
- API-key authentication (SHA-256-hashed, revocable, shown once) with viewer / analyst / admin RBAC.
- Secure-by-default bootstrap: an admin key is generated and logged once (or supplied via
  `ARGUS_BOOTSTRAP_ADMIN_KEY`, minimum 32 characters, otherwise startup fails closed).
- CLI: `--create-api-key NAME --role ROLE` for out-of-band key creation and recovery.
- SSRF egress guard: private/reserved/internal destinations blocked at seed validation, at
  connection time after DNS resolution (defeats DNS rebinding), and for raw-socket modules.
  Opt-in `ARGUS_ALLOW_PRIVATE_TARGETS` / `--allow-private` for authorised internal tests.
- Rules of engagement: scans require a purpose and explicit authorisation, stored with the
  investigation; UI confirmation dialog.
- Tamper-evident, SHA-256 hash-chained audit log (`GET /api/audit`, `GET /api/audit/verify`).
- Per-key scan rate limiting and a server-wide concurrent scan cap (HTTP 429).
- Security headers: strict CSP (`script-src 'self'`), frame denial, nosniff, no-referrer,
  `no-store` on API data, HSTS over HTTPS.
- Single-use, short-lived WebSocket tickets; authenticated exports in the UI.
- Web UI sign-in / sign-out and current-user indicator.
- `SECURITY.md` disclosure policy; `docs/explained/03-platform-security.md`.
- Tests: SSRF, authentication, RBAC, audit tampering, limits, headers, CORS (55 → 120).

### Changed
- CORS is same-origin by default (was `*` with credentials); extra origins via `ARGUS_CORS_ORIGINS`.
- WebSocket handler supervised by an anyio task group (fixes a cancellation race found by stress testing).
- Invalid API keys are audited (rate-limited per IP); anonymous page loads are not.

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
