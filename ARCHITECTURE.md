# Argus System Architecture & Design Specification

> **Project:** Argus OSINT & Visual Link Analysis Platform  
> **Author:** Aspiring Cyber Security & Ethical Hacking Candidate  
> **Target Institutions:** BSc (Hons) Ethical Hacking (Abertay University) & Amazon Cyber Security Degree Apprenticeship

---

## 1. Executive Architecture Summary

Argus is designed as an enterprise-grade, event-driven Open Source Intelligence (OSINT) framework capable of performing automated, recursive reconnaissance across public surface vectors while synthesizing discovered intelligence into an interactive directed property graph.

```
                      ┌────────────────────────────────────────┐
                      │              Argus Core                │
                      │       (CLI / FastAPI Web UI)           │
                      └──────────────────┬─────────────────────┘
                                         │
                         [ Investigation Config & Seed ]
                                         │
                                         ▼
                      ┌────────────────────────────────────────┐
                      │          Argus Recursive Engine        │
                      │  - Async Work Queue (asyncio.Queue)    │
                      │  - Deduplication Cache (SHA-256)       │
                      │  - Depth Enforcement (Hop Control)     │
                      └──────────────┬──────────┬──────────────┘
                                     │          │
                     Emits Events    │          │ Executes Modules
                                     │          │ Concurrently
                                     ▼          ▼
   ┌───────────────────────────────────┐    ┌───────────────────────────────────┐
   │             EventBus              │    │       Reconnaissance Modules      │
   │  - WebSocket Telemetry Streamer   │    │  - Username Hunter (Sherlock)     │
   │  - Real-Time Console Ticker       │    │  - DNS & Mail Recon (aiodns)      │
   └───────────────────────────────────┘    │  - Subdomain Finder (crt.sh CT)   │
                                            │  - IP Intelligence (GeoIP/ASN)    │
                                            │  - RDAP / WHOIS Profiler          │
                                            │  - TLS Certificate Analyzer       │
                                            │  - Web Tech Fingerprinting        │
                                            └─────────────────┬─────────────────┘
                                                              │
                                                Discovered Entities & Relations
                                                              │
                                                              ▼
                                            ┌───────────────────────────────────┐
                                            │        Intelligence Graph         │
                                            │  - Directed Multi-Graph (NetworkX)│
                                            │  - Topological Analytics & Hubs   │
                                            │  - Threat Exposure Scoring        │
                                            │  - Cytoscape.js & Maltego Exports │
                                            └───────────────────────────────────┘
```

---

## 2. Core Architectural Pillars

### 2.1. Directed Property Graph Data Model
In Argus, all intelligence is modeled as a formal mathematical graph $G = (V, E)$:
- **Vertices ($V$):** Intelligence `Entity` instances. Every entity possesses:
  - Deterministic ID derived from: `hash(entity_type + ":" + normalized_value)`. This guarantees $O(1)$ deduplication across recursive crawls.
  - Strict classification via `EntityType` enum: `DOMAIN`, `SUBDOMAIN`, `IP_ADDRESS`, `ASN`, `EMAIL`, `USERNAME`, `SOCIAL_PROFILE`, `PERSON`, `ORGANIZATION`, `CERTIFICATE`, `TECHNOLOGY`, `DNS_RECORD`.
  - Confidence metric ($0.0 \le c \le 1.0$) and origin provenance (`source_module`, discovery timestamp, hop depth).
- **Edges ($E$):** Semantic `Relation` instances. Relationships are strictly typed directed edges via `RelationType`: `RESOLVES_TO`, `SUBDOMAIN_OF`, `HOSTED_ON`, `LOCATED_IN`, `HAS_ACCOUNT`, `BELONGS_TO`, `OPERATES`, `SECURED_BY`, `USES_TECH`, `HAS_DNS_RECORD`.

### 2.2. Event-Driven Asynchronous Pipeline (EDA)
Traditional recon tools suffer from sequential HTTP/DNS blocking. Argus leverages:
- **`asyncio` concurrency with bounded semaphores:** Prevents thread exhaustion and OS socket starvation while maintaining sustained speeds exceeding 50+ concurrent requests.
- **Connection Pooling (`aiohttp.TCPConnector`):** Reuses established TCP connections and TLS sessions with DNS caching for high throughput.
- **Event Bus Decoupling:** Modules do not know about the CLI, Web UI, or storage backend. They simply yield `Entity` and `Relation` objects. The `EventBus` broadcasts lifecycle notifications (`ENTITY_DISCOVERED`, `RELATION_DISCOVERED`, `SCAN_PROGRESS`, `SCAN_COMPLETED`) to all registered listeners.

### 2.3. Bounded Recursive Crawling (Spiderfoot Model)
To prevent combinatorial explosion ("crawling the entire internet"), Argus implements:
1. **Hop Depth Enforcement:** Each discovered entity inherits its parent's depth $+ 1$. Once `depth == max_depth`, the entity is recorded in the graph but suppressed from the queue.
2. **Cycle Detection & Visited Sets:** Normalized hash digests are checked against `_processed_ids` prior to module dispatch.
3. **Smart Module Dispatch:** Each module declares `supported_entity_types`. The engine only passes entities to eligible collectors (e.g., DNS modules only accept `DOMAIN` or `SUBDOMAIN`; Sherlock hunter only accepts `USERNAME`).

### 2.4. Real-Time WebSocket Telemetry
- Rather than forcing users to wait for a 5-minute scan to finish, Argus streams discoveries via WebSockets directly into **Cytoscape.js**.
- Nodes and edges animate into view instantaneously as network responses arrive, paired with a live terminal activity log.

---

## 3. Offensive Security & OSINT Design Considerations

| Capability | Threat Intel / Offensive Security Value | Defensive Engineering Counterpart |
| :--- | :--- | :--- |
| **Certificate Transparency** | Identifies unlinked staging/dev subdomains without sending a single packet to the target | Zero active footprint; leverages public append-only cryptographic CT logs (`crt.sh`) |
| **TLS SAN Extraction** | Discovers internal hosts and multi-tenant architectures | Validates certificate expiration and rogue domain hijacking |
| **Email & Gravatar Correlation** | Links corporate personas to personal hobbies, forums, and developer platforms | Assesses phishing vulnerability and credential stuffing risk |
| **HTTP Security Header Audit** | Evaluates missing defense-in-depth mitigations (HSTS, CSP, XFO) | Computes quantitative attack surface posture grade (A+ to F) |
| **Topological Centrality** | Uncovers "Crown Jewel" assets and single points of failure (pivotal domains/IPs) | Degree centrality and bridge-node detection |

---

## 4. Software Engineering Best Practices

- **Strict Type Hints (`typing` & `mypy` style):** All models are built on Pydantic v2 schemas.
- **Error Isolation:** Network failures, DNS timeouts, and HTTP 5xx errors in one module never terminate the scan pipeline.
- **Containerization:** Production Docker image with non-root security principles (`useradd argus`) and minimal slim base.
- **Test Coverage:** Automated unit test suite validating graph data structures, deterministic hashing, heuristic classifiers, and event dispatch.
