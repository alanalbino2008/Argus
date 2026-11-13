# 03 — Securing the Platform Itself (Plain-English Guide)

> Purpose: explain how Argus protects itself, its users, and the people it investigates.
> This is the chapter most relevant to an *ethical hacking* degree — lead with it in interviews.

## 1. Threat model: who could abuse Argus, and how?

| Threat | Example | Control |
|---|---|---|
| Anyone on the network uses your instance | Launches scans from *your* IP, reads your investigations | API keys (authentication) |
| A colleague exceeds their role | A viewer deletes evidence | Roles (RBAC) |
| Argus is aimed at the server's own network | Scan `169.254.169.254` to steal cloud credentials | Egress guard (SSRF protection) |
| Someone scans without permission | Harassing a person or company | Rules of engagement + audit trail |
| An insider covers their tracks | Edits the log to hide a scan | Hash-chained, tamper-evident audit log |
| A hostile target attacks the analyst | Script in a DNS TXT record (stored XSS) | Output escaping + Content-Security-Policy |
| Resource exhaustion | 1,000 scans in a loop | Rate limits and concurrent scan cap |

> **Interview line:** "I threat-modelled Argus as attack surface in its own right: it ingests
> attacker-controlled data and makes network requests on a user's behalf, which makes it a
> natural SSRF and stored-XSS target."

## 2. Authentication — API keys

* A key looks like `argus_` + 43 random characters (**256 bits** of randomness, from Python's `secrets`).
* The database stores only its **SHA-256 hash**. If the database leaks, the keys don't.
* *"Why not bcrypt?"* Slow hashes protect weak, human-chosen passwords. A 256-bit random key
  can't be brute-forced, so a fast hash is the industry norm (GitHub and Stripe do the same).
* Keys are shown **once**, can be **revoked**, and record when they were last used.
* **First start:** no default password ships with Argus. If no admin key exists, one is
  generated and printed once in the log (or supplied via `ARGUS_BOOTSTRAP_ADMIN_KEY`, which must
  be ≥ 32 characters — Argus *refuses to start* with a weak one: "fail closed").
* **Lost every key?** `python -m argus.cli.console --create-api-key recovery --role admin`
  works out-of-band, directly against the database.

## 3. Authorisation — roles (RBAC)

| Role | Can |
|---|---|
| viewer | read investigations, graphs, exports |
| analyst | + launch and cancel scans |
| admin | + delete investigations, manage keys, read the audit log |

This is the **principle of least privilege**: give each person the minimum they need. You can't
revoke the last admin key, so you can't lock yourself out.

## 4. SSRF — the most important fix in this phase

**Server-Side Request Forgery** = tricking a server into making requests *for* you. Argus's
whole job is making requests to targets, so before Phase 3 anyone able to start a scan could
make the server fetch `http://169.254.169.254/` — the **cloud metadata service**, which hands
out the server's cloud credentials. (This is how the 2019 Capital One breach happened.)

Argus now blocks private, loopback, link-local, carrier-grade-NAT, multicast and reserved
addresses, and internal names like `localhost`, `*.internal` and `*.local`, at **three layers**:

1. **Seed validation** – the scan request is refused up front (HTTP 422, audited).
2. **At connection time** – a custom DNS resolver checks every address *after* resolution, the
   exact addresses the socket will use. This defeats **DNS rebinding**, where an innocent-looking
   public domain is pointed at `10.0.0.5`.
3. **IP literals and raw sockets** – checked directly; the TLS module connects to the vetted IP
   rather than re-resolving the name.

Tricky cases are covered by tests: `::ffff:127.0.0.1` (loopback disguised as IPv6), mixed DNS
answers (public + private: only the public one is used), and the configured outbound proxy
(trusted, even though it's internal).

Authorised internal assessments can opt in with `ARGUS_ALLOW_PRIVATE_TARGETS=true` (API) or
`--allow-private` (CLI).

## 5. Rules of engagement

Ethical hacking = **permission**. Every scan must include a stated purpose ("HackerOne programme
X", "CTF", "our own infrastructure") and an explicit "I am authorised" confirmation. Both are
stored with the investigation and in the audit log. It doesn't *prove* authorisation — nothing
can — but it creates accountability, which is exactly what real penetration-testing firms do
with signed scope documents.

## 6. Tamper-evident audit log

Every security-relevant action is recorded: scans (allowed *and* denied), cancels, exports,
deletions, key changes, denied access and invalid keys. Each entry stores the **hash of the
previous entry**, forming a chain:

```
entry 1: hash = SHA256(000…0     + entry1)
entry 2: hash = SHA256(hash1     + entry2)
entry 3: hash = SHA256(hash2     + entry3)
```

Change entry 2 and its hash no longer matches, so neither does every hash after it.
`GET /api/audit/verify` recomputes the chain and reports the first broken entry. A test proves
this by editing a row directly in the database. (It's the same principle as git commits or a
blockchain.)

*Limitation to mention honestly:* an attacker with full database access could rewrite the
*entire* chain. The fix is to periodically ship the latest hash somewhere they can't reach
(e.g. a SIEM) — a sensible next step.

## 7. Browser hardening

* **Content-Security-Policy** `script-src 'self'`: the browser runs *only* scripts served by
  Argus. Even if an XSS bug slipped through, an injected script would be refused. This was only
  possible because Phase 2 vendored Cytoscape instead of loading it from a CDN.
* `frame-ancestors 'none'` / `X-Frame-Options: DENY` → no clickjacking.
* `Cache-Control: no-store` on API responses → investigation data never sits in a browser cache.
* **CORS** is same-origin only unless origins are listed explicitly (it was previously `*`).
* **WebSockets:** browsers can't send auth headers on WebSockets, and putting the API key in the
  URL would leak it into logs. The page trades its key for a **one-time ticket valid 30 seconds**.

## 8. Abuse limits

* Per-key rate limit on launching scans (default 10/minute) → HTTP 429 with `Retry-After`.
* Server-wide cap on concurrent scans (default 5).
* Failed-login auditing is itself rate-limited per IP, so an attacker can't flood the audit log.

## 9. Bug found along the way: a flaky test that was a real design flaw

One WebSocket test failed only when the machine was busy. Instrumenting it showed the handler
received **two** cancellations: it had mixed plain `asyncio` tasks with Starlette's `anyio`
structured concurrency. The fix was to supervise the WebSocket's sender/receiver with an anyio
**task group**, so cancellation propagates correctly. The lesson: *never "fix" a flaky test with
retries or sleeps — find out why it's flaky.*

## 10. Questions you might be asked

* **"What's SSRF and how did you prevent it?"** See §4 — mention DNS rebinding and the metadata service.
* **"Where do you store API keys?"** Only a SHA-256 hash; the plaintext is shown once.
* **"How would you scale the rate limiter across servers?"** Move it (and the audit chain head) into Redis/PostgreSQL.
* **"What would you add next?"** SSO (OIDC), key expiry, shipping audit hashes to a SIEM, and per-investigation access control.
