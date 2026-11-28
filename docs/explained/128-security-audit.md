# Security audit: what was tested, what was fixed

Argus was attacked the way an outsider would attack it. Every one of the 381 API operations was called with
no credentials, with a viewer key and with an analyst key. The admin and owner pages were probed. Forged
headers, oversized bodies, password and key guessing, and redirect tricks were tried against a real
server. The code was also searched for the classic flaws. This page lists what held, what did not, and
what changed.

## "What happens if someone types /admin?"

`/admin` opens the **owner console sign-in page** and nothing else. Every owner operation behind it
returned **401** to an anonymous caller, even when sent a well-formed request. Signing in needs the
owner's email, password and a 2FA code, and repeated attempts are throttled. The same goes for every
other path that looks interesting (`/api/keys`, `/api/audit`, `/api/settings`...):

| Caller | Result |
|---|---|
| Nobody (no key) | 293 of 381 operations: **401**. 38: **404** (feature switched off). The 7 that answer are meant to be public: sign-in configuration, sign-out, the report-signing public key, and the liveness and health probes |
| Viewer key | **403** on all 134 operations that change data; none can raise its own role |
| Analyst key | **403** on everything admin-only (keys, members, settings, audit log, deletion) |

## Held up — no change needed

- **Injection:** no shell commands built from input, no `eval`, no pickle, no unsafe YAML. XML is parsed with
  `defusedxml` everywhere. Archives are unpacked with Python's safe `data` filter. Database access is
  parameterised throughout.
- **Passwords and keys:** passwords are hashed with scrypt and API keys with SHA-256. Comparisons are
  constant-time. No secrets are committed to the repository or written to the logs.
- **Browser:** a strict Content Security Policy (no inline scripts, no third parties) and
  `X-Frame-Options: DENY`. The UI escapes everything it shows. Cookies are `HttpOnly`, `SameSite` and
  `Secure` over HTTPS. CORS is off unless origins are listed. Uploaded evidence is shown inline only for
  plain images, in a sandbox; everything else is downloaded.

## Found and fixed

| # | Weakness | Impact | Fix |
|---|---|---|---|
| 1 | **Forged client IP.** The container and Helm chart told the server to believe `X-Forwarded-For` from *anyone* (`--forwarded-allow-ips "*"`) | Proven live: a key allowed only from `10.99.0.0/16` worked from anywhere with `X-Forwarded-For: 10.99.1.1`. The same trick defeated every per-address rate limit and sign-in lockout (rotate a fake IP per attempt), and wrote false addresses into the audit log | The header is believed only from trusted proxies. Container: loopback only (`FORWARDED_ALLOW_IPS=127.0.0.1`). Helm: `config.trustedProxies`, private ranges by default. Cluster compose: the private network the load balancer is on |
| 2 | **Open redirect after sign-in.** `/\t/evil.example` passed the return-path check, and browsers drop the tab and go to `//evil.example` | A phishing link that lands on the real sign-in page and sends the user to a look-alike site afterwards | Any control character or whitespace is refused, as is anything a URL parser reads as a scheme or host |
| 3 | **No request size limit** | Proven live: one anonymous 64 MB request added about 200 MB to the server's memory. A few in parallel could crash it | Bodies over **4 MB** (`ARGUS_MAX_REQUEST_KB`) are refused with **413** before they are read. Uploads get the evidence limit plus 1 MB. Streamed bodies with no length are cut off at the limit; three 64 MB streams left memory flat |
| 4 | **Unlimited API-key guessing** | Keys are long and random, so guessing is hopeless. But nothing stopped it or made it visible | 30 wrong keys from one address in 5 minutes lock that address out with **429** for the rest of the window. During the lockout even a correct key is refused, so the lock tells a guesser nothing |
| 5 | **Health check said too much** | Anyone could read the exact version and database type, which helps pick an exploit | Anonymous callers get only up/down. Signed-in users and the internal network get the details |
| 6 | **Metrics open to the internet** when no token was set | Request rates, route names and internals were readable by anyone | With no token, `/metrics` answers only loopback and private networks (Prometheus in the cluster) or a signed-in admin. To everyone else it is a 404 |
| 7 | **Development mode exposed** | `ARGUS_AUTH_ENABLED=false` made every caller an administrator, from anywhere | Dev mode now serves only this machine and private networks. Public addresses get **403** |
| 8 | **Server banner** | `server: uvicorn` named the software | No longer sent |
| 9 | **API map always public** | `/docs` and `/openapi.json` list every endpoint (they hold no data) | New `ARGUS_API_DOCS_ENABLED=false` switch hides them |

## If you run Argus behind a load balancer

Set the proxy's address or subnet, so Argus sees real client addresses:

- **Docker:** `-e FORWARDED_ALLOW_IPS=10.0.0.5` (comma-separated IPs or CIDRs).
- **Helm:** `--set config.trustedProxies=10.42.0.0/16`, narrowed to your ingress controller's pods.
- **Never `*`.** That lets anyone choose the address Argus sees.

If the setting is wrong, nothing breaks open. Argus just sees the proxy's address for everyone, so
per-address limits apply to everyone together.

## Tested

`tests/test_security_hardening.py` covers each fix: 13 redirect payloads, oversized bodies with and
without a length, lockout and its edges, minimal health, hidden metrics, dev-mode reach, and the
deployment files. The attacks were also re-run against a live server, and each one now fails.
