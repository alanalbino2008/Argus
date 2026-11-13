# 01 — The Engine & Reliability Layer (Plain-English Guide)

> Purpose: so you can confidently explain *how Argus works and why it was built this way* in an interview.

## 1. The big picture in one paragraph

You give Argus one starting point (the **seed**), e.g. `example.com`. Argus runs every
module that understands that kind of thing (DNS, WHOIS, TLS…). Each module reports what it
found — new **entities** (an IP address, a subdomain) and **relations** between them
("example.com RESOLVES_TO 93.184.216.34"). New entities go back into a **queue** so they
can be investigated too. That loop is called *recursive enrichment*, and `max_depth`
controls how many "hops" away from the seed Argus is allowed to go.

## 2. Why the engine was rewritten

**Before:** the engine took one entity off the queue, finished it completely, then took the
next. If one website took 30 seconds to answer, *everything* waited 30 seconds.

**After:** a **worker pool**. Think of a restaurant kitchen: instead of one chef cooking every
order start-to-finish, there are N chefs (`concurrency_limit`, default 15) taking orders from
the same ticket rail (the `asyncio.Queue`). The scan ends when the rail is empty *and* every
chef is finished (`queue.join()`).

> **Interview line:** "I used a producer/consumer worker pool over an `asyncio.Queue` and
> wait on `Queue.join()` for completion, so discoveries are expanded in parallel rather than
> sequentially. The tests prove a 10-entity scan finishes in ~0.6s instead of ~3.3s."

### Why `asyncio` and not threads?
OSINT is **I/O-bound** — the program spends almost all its time *waiting for the network*.
`asyncio` lets one thread juggle thousands of waiting requests cheaply. Threads would add
memory overhead and locking problems for no benefit.

## 3. The safety features (and the problem each one solves)

| Feature | Problem it solves | Where |
|---|---|---|
| **Module timeout** | A data source that never answers would freeze the scan forever. Each module run gets a hard time limit (`asyncio.wait_for`). | `engine.py → _execute_module` |
| **Circuit breaker** | If a module fails 5 times in a row (e.g. the API is down), it's switched off for the rest of the scan instead of wasting time. Same idea as an electrical circuit breaker. A standard pattern in microservices (Netflix Hystrix). | `engine.py → _record_failure` |
| **Entity cap** | A scan of a huge company could discover 100,000+ things and run out of memory. `max_entities` stops it and marks the result `truncated`. | `engine.py → _ingest_entity` |
| **Cancellation** | Users need a "stop" button. Cancellation is *cooperative*: the engine sets a flag, workers stop cleanly, and partial results are kept. | `engine.cancel()`, `POST /api/investigation/{id}/cancel` |
| **Clear end states** | Previously a crashed scan stayed "running" forever. Now every scan ends as `completed`, `cancelled` or `failed`. | `engine.py → start` |

### Success, degraded or failed?
Modules deliberately *swallow* errors from individual sources — if crt.sh is down, we still
want HackerTarget's results. But that hid failures: "found nothing" looked the same as
"every source was down", so the circuit breaker never fired.

Fix: each module run gets a **report card** (`ModuleRunReport`, stored in a Python
`ContextVar` so it follows the run into helper tasks automatically). The shared HTTP client
ticks it for every request. At the end the engine grades the run:

| Grade | Meaning | Counts toward circuit breaker? |
|---|---|---|
| success | no source errors | no |
| degraded | some sources failed, but we got results | no (logged as a warning) |
| failed | every source failed and nothing was found | **yes** |

It also fixed a real bug: a DNS *timeout* used to record a domain as having "no valid MX
records", which falsely raised its risk score. Now a timeout means "unknown".

## 4. The resilient HTTP client (`argus/core/http.py`)

Every module now talks to the internet through one shared `HttpClient`.

1. **Retries with exponential backoff + jitter.** If a server returns *503 Service Unavailable*
   or the connection drops, try again after 0.5s, then ~1s, then ~2s… The wait is randomised
   ("jitter") so that many requests don't all retry at the same instant (the
   *thundering herd* problem). Errors like *404 Not Found* are **not** retried — retrying
   won't change the answer.
2. **`Retry-After`.** When a server says *429 Too Many Requests — retry after 10 seconds*,
   Argus obeys, and slows down **every** request to that host, not just the one that failed.
3. **Per-host rate limiting.** A minimum gap between requests to the same website, plus a cap
   on simultaneous connections per site. This is about being a responsible tool: hammering
   a free service like crt.sh gets you blocked — and is arguably abusive.
4. **Telemetry.** Counts requests, retries, throttles, failures and status codes so you can
   *prove* how the scan behaved.
5. **Proxy support.** Honours `HTTPS_PROXY`, which corporate networks require.

> **Interview line:** "Modules don't each implement retry logic. I centralised resilience in
> one HTTP layer with the same interface as aiohttp, so every current and future module
> gets retries, back-off and rate limiting for free — separation of concerns."

## 5. How it's tested (without touching the internet)

Tests must be **deterministic** — they can't depend on whether GitHub is up today.

* `tests/test_engine.py` plugs in **fake modules** (one that fans out, one that hangs forever,
  one that always crashes) to prove depth limits, de-duplication, parallelism, timeouts,
  the circuit breaker, the entity cap and cancellation.
* `tests/test_http.py` spins up a **tiny local web server** that deliberately returns 503s and
  429s to prove the retry, back-off and rate-limit logic.
* `tests/test_api.py` checks the REST API rejects bad input (422), unknown IDs (404) and
  handles the cancel lifecycle (409 if already stopped).

Run them all: `pytest -v`

## 6. Questions you might be asked

* **"What happens if two modules find the same IP?"** Entity IDs are a SHA-256 hash of
  type + normalised value, so the second discovery is merged into the first, never duplicated.
* **"Why not retry everything?"** Retrying non-transient errors (404, bad TLS cert) wastes time
  and load; only 429/5xx/connection errors are retried.
* **"How do you stop Argus being used to attack someone?"** Rate limiting is one layer; Phase 3
  adds authentication, scope/authorisation confirmation and an audit log.
* **"What's the biggest remaining weakness?"** Results are only in memory — Phase 2 adds a
  database so scans survive restarts.
