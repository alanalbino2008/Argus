# 👁️ Argus: Autonomous OSINT Reconnaissance & Graph Link Analysis

[![Python Version](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue?logo=python)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi)](https://fastapi.tiangolo.com/)
[![Cytoscape](https://img.shields.io/badge/Cytoscape.js-3.28-orange?logo=javascript)](https://js.cytoscape.org/)
[![Tests](https://img.shields.io/badge/Tests-14%20Passed%20(100%25)-success)](#testing--verification)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> *"Named after Argus Panoptes, the hundred-eyed all-seeing giant of Greek mythology, Argus is a next-generation Open Source Intelligence (OSINT) platform that unites rapid credential hunting, multi-hop infrastructure enrichment, and interactive topological relationship graphing into a single, lightning-fast platform."*

---

## 🌟 Vision & Key Capabilities

Argus bridges the gap between fragmented CLI tools and expensive enterprise intelligence suites by fusing the best features of industry standards with modern web-scale engineering:

* ⚡ **Sherlock-Class Identity Hunting:** Asynchronous, concurrent account hunting across 60+ platforms (GitHub, GitLab, DockerHub, PyPI, Bluesky, Telegram, Keybase, etc.) with smart false-positive rejection.
* 🕸️ **Spiderfoot-Style Recursive Infrastructure Mapping:** Automated multi-hop enrichment: Domain ➔ DNS ➔ IP ➔ GeoIP/ASN ➔ RDAP Registrant ➔ Subdomains via Certificate Transparency ➔ TLS SANs ➔ Web Tech Stack.
* 🔮 **Maltego-Grade Visual Link Analysis:** Interactive physics-driven graph visualization built on **Cytoscape.js** with real-time WebSocket telemetry streaming. Nodes and relationships animate live onto the canvas as intelligence is discovered.
* 🛡️ **Novel Innovation — Attack Surface Scoring & Pivot Analysis:** Topological analysis utilizing graph degree centrality to identify single-point-of-failure infrastructure hubs, detect missing defensive headers (HSTS, CSP), and calculate a quantitative exposure score.
* 🔄 **Enterprise Interoperability:** Export complete knowledge graphs to standardized JSON or **Maltego-compatible CSV format** with one click.

---

## 🏗️ System Architecture

```mermaid
graph TD
    User([OSINT Analyst]) -->|Target Seed| Engine[Argus Recursive Engine]
    Engine --> Bus[Async EventBus]
    
    subgraph Reconnaissance Modules
        Engine --> Mod1[Username Hunter]
        Engine --> Mod2[DNS & DMARC Interrogator]
        Engine --> Mod3[Subdomain CT Finder]
        Engine --> Mod4[IP Intelligence & ASN]
        Engine --> Mod5[RDAP / WHOIS Profiler]
        Engine --> Mod6[TLS Certificate Inspector]
        Engine --> Mod7[HTTP Tech Fingerprinter]
    end

    Mod1 & Mod2 & Mod3 & Mod4 & Mod5 & Mod6 & Mod7 -->|Entities & Relations| Graph[(Intelligence Graph - NetworkX)]
    Graph --> Analytics[Graph Analyzer & Risk Scorer]
    
    Bus -->|Real-time Stream| WS[WebSocket Telemetry]
    WS --> WebUI[Cytoscape.js Interactive Dashboard]
    Bus --> CLI[Rich Terminal Output]
```

### Reliability & Resilience Engineering

| Concern | How Argus handles it |
|---|---|
| **Throughput** | A pool of async workers (`concurrency_limit`) expands entities in parallel; every eligible module runs concurrently per entity. |
| **Slow / hung data sources** | Hard per-module wall-clock timeout (`module_timeout_seconds`). |
| **Transient failures** | Shared `HttpClient` retries 429/5xx and connection errors with exponential backoff + full jitter, honouring `Retry-After`. |
| **Being a good network citizen** | Per-host rate limiting and per-host concurrency caps; a 429 slows *all* callers for that host. |
| **Repeatedly broken modules** | Circuit breaker disables a module after N consecutive failures. |
| **Graph explosions** | `max_entities` safety cap with explicit `truncated` flag. |
| **Control** | Cooperative cancellation (`POST /api/investigation/{id}/cancel`) and explicit `completed` / `cancelled` / `failed` states. |
| **Observability** | Per-module stats (runs, failures, timeouts, latency) and HTTP stats (requests, retries, throttles, status codes) on every investigation. |
| **Corporate networks** | Honours `HTTP(S)_PROXY` / `NO_PROXY`. |

Plain-English walkthroughs: [engine & reliability](docs/explained/01-engine-and-reliability.md) · [persistence & history](docs/explained/02-persistence-and-history.md).

### Persistence & History

Every investigation is stored in a database (SQLite by default, PostgreSQL via `ARGUS_DATABASE_URL`), checkpointed every second while it runs, and survives restarts. The web UI's **History** tab reopens any past investigation, and the inspector shows every *other* investigation in which the same IP, email or domain appeared.

| Method & path | Purpose |
|---|---|
| `POST /api/scan` | Launch an investigation |
| `GET /api/investigations?status=&target=&limit=&offset=` | Investigation history |
| `GET /api/investigation/{id}` | Status, stats, errors and warnings |
| `POST /api/investigation/{id}/cancel` | Cancel a running scan |
| `DELETE /api/investigation/{id}` | Delete an investigation and its findings |
| `GET /api/investigation/{id}/graph` · `/export/json` · `/export/csv` | Graph and exports |
| `GET /api/entities/search?q=&type=` | Cross-investigation entity pivot |
| `GET /api/health` | Liveness/readiness probe (public) |
| `GET /api/me` · `POST /api/ws-ticket` | Current identity · one-time WebSocket ticket |
| `GET/POST /api/keys` · `DELETE /api/keys/{id}` | API-key management (admin) |
| `GET /api/audit` · `GET /api/audit/verify` | Audit trail and tamper check (admin) |
| `WS /ws/stream/{id}?ticket=` | Snapshot of findings so far, then live events |

| Setting (env var) | Default |
|---|---|
| `ARGUS_DATABASE_URL` | `sqlite+aiosqlite:///./argus.db` |
| `ARGUS_PERSIST_FLUSH_INTERVAL` | `1.0` seconds |
| `ARGUS_WS_QUEUE_SIZE` | `2000` messages per client |

---

### Security Model

Argus ingests attacker-controlled data and makes outbound connections on a user's behalf, so the platform itself is treated as attack surface.

| Control | Implementation |
|---|---|
| **Authentication** | API keys (`Authorization: Bearer`), 256-bit random, stored only as SHA-256 hashes; revocable |
| **Authorisation (RBAC)** | `viewer` (read) · `analyst` (+ scan/cancel) · `admin` (+ delete, keys, audit) |
| **Rules of engagement** | Every scan requires a stated purpose and explicit confirmation of authorisation |
| **SSRF / egress guard** | Private, loopback, link-local (cloud metadata), CGNAT and internal hostnames blocked at seed validation *and* at connection time after DNS resolution (defeats DNS rebinding); opt-in `ARGUS_ALLOW_PRIVATE_TARGETS` for authorised internal tests |
| **Audit trail** | Append-only, SHA-256 hash-chained log of scans, exports, deletions, key changes and denied requests; `GET /api/audit/verify` detects tampering |
| **Abuse limits** | Per-key scan rate limit and a server-wide concurrent scan cap (HTTP 429) |
| **Browser hardening** | Strict CSP (`script-src 'self'`), `frame-ancestors 'none'`, `nosniff`, `no-referrer`, `Cache-Control: no-store` on API data; HSTS over HTTPS; output escaping of all OSINT data |
| **CORS** | Same-origin by default; extra origins must be listed explicitly (`ARGUS_CORS_ORIGINS`) |
| **WebSockets** | Single-use, 30-second tickets instead of long-lived keys in URLs |

See [`docs/explained/03-platform-security.md`](docs/explained/03-platform-security.md) and [`SECURITY.md`](SECURITY.md).

| Security setting (env var) | Default |
|---|---|
| `ARGUS_AUTH_ENABLED` | `true` |
| `ARGUS_BOOTSTRAP_ADMIN_KEY` | *(unset → generated and logged once)* |
| `ARGUS_ALLOW_PRIVATE_TARGETS` | `false` |
| `ARGUS_CORS_ORIGINS` | `[]` |
| `ARGUS_MAX_CONCURRENT_SCANS` / `ARGUS_SCANS_PER_MINUTE` | `5` / `10` |

---

## 🚀 Quickstart & Installation

### Option 1: Local Python Environment (Recommended)

```bash
# 1. Clone repository
git clone https://github.com/alanalbino2008/Argus.git
cd Argus

# 2. Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Option 2: Docker / Container Deployment

```bash
# Run one-command containerized stack
docker compose up -d

# Open http://localhost:8000 in your browser
```

---

## 💻 Usage

### 1. Interactive Web Dashboard (Maltego in the Browser)

Launch the web platform and API server:

```bash
python -m argus.cli.console --serve
```

Then visit **`http://127.0.0.1:8000`** in your browser.

> **First start:** Argus is secure by default. If no admin key exists, one is generated and printed **once** in the server log — paste it into the sign-in screen, then create personal keys (`POST /api/keys`) and revoke the bootstrap key. Lost every admin key? `python -m argus.cli.console --create-api-key recovery --role admin`.

* Enter any target (**Domain**, **Username**, **Email**, or **IP Address**).
* Choose maximum hop depth (1 to 3).
* Click **Launch Recon**, state the engagement purpose and confirm you are authorised (recorded in the audit log), then watch the directed graph expand and animate in real time!
* Click any node to open the **Entity Inspector** and inspect confidence ratings, discovery origins, and enriched metadata.
* Switch to **Threat Intel** to view graph pivots, risk exposure score, and export to JSON or Maltego CSV.

---

### 2. High-Speed Terminal CLI

Argus includes a **Rich** command-line interface with automatic entity type detection, progress bars, and formatted tables:

```bash
# Scan a domain (Recursion Depth: 1)
python -m argus.cli.console example.com -d 1

# Sherlock-style username hunting across 60+ platforms
python -m argus.cli.console torvalds -t username

# Scan an IP address with JSON export
python -m argus.cli.console 1.1.1.1 --export-json ip_report.json

# Investigate an email address and export Maltego CSV
python -m argus.cli.console security@example.com --export-csv maltego_export.csv
```

---

## 🔍 Module Breakdown

| Module | Primary Input | Discoveries & Enriched Entities | Technique / Protocol |
| :--- | :--- | :--- | :--- |
| **`username_hunter`** | `USERNAME` | `SOCIAL_PROFILE`, `HAS_ACCOUNT` | Concurrent async HTTP probes with false-positive heuristics |
| **`github_hunter`** | `USERNAME` | `PERSON`, `EMAIL` (commits), `ORGANIZATION`, `DOMAIN` | Mines public events, unmasks commit emails, queries keys |
| **`phone_recon`** | `PHONE` | `ORGANIZATION` (Carrier/Region), `LOCATED_IN` | International E.164 parsing, dial codes, telecom carrier mapping |
| **`shodan_internetdb`** | `IP_ADDRESS` | `PORT`, `VULNERABILITY` (CVEs), `DOMAIN` (Hostnames) | Passive Shodan exposure API querying open ports and known CVEs |
| **`dns_recon`** | `DOMAIN`, `SUBDOMAIN` | `IP_ADDRESS`, `DOMAIN` (MX/NS), `DNS_RECORD` (SPF/DMARC) | Asynchronous DNS resolution via `dnspython` |
| **`subdomain_finder`** | `DOMAIN` | `SUBDOMAIN`, `SUBDOMAIN_OF` | Passive Certificate Transparency log indexing (`crt.sh`) |
| **`ip_intelligence`** | `IP_ADDRESS` | `ASN`, `ORGANIZATION`, `DOMAIN` (PTR) | Reverse DNS + BGP autonomous system & GeoIP resolution |
| **`whois_lookup`** | `DOMAIN` | `ORGANIZATION` (Registrar/Registrant), `EMAIL` (Abuse) | RFC 7480 RDAP protocol queries |
| **`tls_analyzer`** | `DOMAIN`, `SUBDOMAIN` | `CERTIFICATE`, `SUBDOMAIN` (via SANs) | TLS handshake on 443, certificate chain extraction |
| **`http_fingerprint`** | `DOMAIN`, `IP_ADDRESS` | `TECHNOLOGY` (Web Server, CDN, Framework) | Header analysis, HSTS/CSP defense audit & letter grade (A+ to F) |
| **`email_recon`** | `EMAIL` | `USERNAME`, `DOMAIN`, `SOCIAL_PROFILE` | RFC email parsing, disposable domain check, Gravatar profiling |

---

## 🧪 Testing & Verification

Argus is backed by an automated test suite verifying Pydantic models, deterministic entity IDs, graph topology metrics, and module logic:

```bash
pytest -v
```

```text
tests/test_graph.py::test_graph_add_entity_and_deduplication PASSED      [  9%]
tests/test_graph.py::test_graph_relations_and_neighbors PASSED           [ 18%]
tests/test_graph.py::test_cytoscape_elements_serialization PASSED        [ 27%]
tests/test_graph.py::test_maltego_csv_export PASSED                      [ 36%]
tests/test_models.py::test_deterministic_entity_id PASSED                [ 45%]
tests/test_models.py::test_entity_creation PASSED                        [ 54%]
tests/test_models.py::test_relation_creation PASSED                      [ 63%]
tests/test_models.py::test_scan_config_validation PASSED                 [ 72%]
tests/test_modules.py::test_detect_target_type PASSED                    [ 81%]
tests/test_modules.py::test_http_fingerprint_security_headers_grading PASSED [ 90%]
tests/test_modules.py::test_event_bus_dispatch PASSED                    [100%]

============================= 11 passed in 0.97s ==============================
```

---

## 🎯 Academic & Professional Portfolio Context

This project was built from the ground up as a practical portfolio project to demonstrate readiness for:
* **BSc (Hons) Ethical Hacking at Abertay University** (Demonstrating network protocol comprehension, passive reconnaissance principles, and defensive engineering).
* **Cyber Security Degree Apprenticeship at Amazon** (Demonstrating Amazon Leadership Principles: *Dive Deep*, *Customer Obsession*, *Ownership*, and scalable asynchronous system design).

For interview presentation notes and STAR-method responses, refer to [`PORTFOLIO_GUIDE.md`](./PORTFOLIO_GUIDE.md) and [`ARCHITECTURE.md`](./ARCHITECTURE.md).

---

## ⚖️ Legal & Ethical Notice

Argus is developed strictly for authorized security research, educational exploration, threat intelligence, and defensive posture evaluation. All data collection mechanisms leverage publicly available endpoints, standard protocols (DNS, RDAP, HTTP), and public Certificate Transparency logs. Users are responsible for complying with all applicable local, national, and international laws.
