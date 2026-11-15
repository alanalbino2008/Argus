# 29 — Investigator Safety (Plain-English Guide)

> Purpose: explain how Argus keeps investigators from being noticed by the people they
> investigate. Useful for questions like:
> * "can the person I'm looking into tell?"
> * "how does Argus use Tor?"
> * "what is an anonymous case?"
> * "how do you know the route actually hides you?"

## 1. Why this matters

Every website keeps a log of who visits: their address, their browser, the time. Someone who
expects to be investigated (a fraudster, a disinformation network, a company hiding something)
watches those logs. If they see visits from a newsroom, from a police force's network, or from a
server that can be traced to an investigator, they can:
* take the evidence down before it is captured;
* show the investigator something different from everyone else;
* find out who is looking, and go after them or their sources.

Professional investigators guard against this with **operational security** ("OPSEC"): they never
let their own identity touch what they are investigating. Phase 28 already kept the investigator's
own laptop out of it (Argus's server visits pages instead). Phase 29 hides the **server** too.

## 2. Routes: Tor, a VPN or a proxy

The operator sets up **routes**: ways out to the internet that hide where a request comes from.

| Kind | What the website sees | Who could know it was you |
|---|---|---|
| **Direct** | this server's address | the website, and anyone it shares logs with |
| **Tor** | a Tor exit relay | no single party: Tor's relays each know only part of the path |
| **VPN or proxy** | the VPN's address | whoever runs the VPN |

Investigators only ever see a route's **name** ("tor", "vpn-de"), never its address or password,
and routes are never saved with a scan, so they cannot leak from the database.

Each **case** has a route, used by every capture and scan in it. A single capture or scan can
choose another route, and every capture records which route it used, in its fingerprinted
record.

## 3. Anonymous cases

A case can be made **anonymous**: nothing in it may touch its subjects directly.
* Captures must use an anonymous route (Tor, or a VPN the operator trusts and marks anonymous).
  A capture that would go direct is **refused before anything is sent**: the safe choice never
  depends on remembering to pick the right option.
* Scans started for the case go through the route, are **passive** (only public sources, never
  the subject's own servers), and are linked to the case.

If a route is down, the capture fails with a clear message. Argus **never falls back** to a
direct connection.

## 4. Blending in

A route hides the address, but a browser also describes itself. Before this phase, captures
announced "Argus-Capture" in their browser identity, which told the subject exactly what was
looking. Now captures, and every request of a routed scan, look like the most common visitor on
the internet:
* an ordinary **Chrome on Windows** browser identity, even replacing identities that individual
  scan modules set themselves;
* **US English** language and the **UTC** timezone, so the server's location doesn't show through
  the page's JavaScript;
* **WebRTC** (which can reveal a computer's real address around a proxy) limited to the proxy, and
  DNS prefetching switched off.

A test loads a page that reports its timezone, language and browser identity through a route, and
checks it sees UTC, en-US and an ordinary Chrome.

## 5. Checking a route actually works

Settings → **Investigator safety** → **Test** asks an "IP echo" service (by default the Tor
Project's) who is calling, twice: through the route, and directly. It shows:
* the address websites see through the route;
* this server's own address;
* whether the route is a real Tor exit.

If the two addresses are the same, the route **leaks**, and Argus says so in red. A test sets up
a deliberately leaky route and checks it is caught.

## 6. Details that matter

* **No DNS leak through Tor.** Looking up a website's address normally asks the local network's
  DNS server, which would learn which sites are being investigated even though the visit itself
  went through Tor. For Tor routes Argus passes the name to Tor unresolved, and Tor looks it up at
  the far end. A test makes any local lookup fail and checks the capture still works.
* **Still no access to internal systems.** A route must not become a way into the server's own
  network. Internal and private addresses (such as the cloud metadata service) are refused before
  anything reaches the route; a test checks they never arrive at it.
* **Connections the route can't carry are skipped.** One scan module (TLS certificate analysis)
  opens its own connections. On a routed scan it is skipped, and the scan says so, rather than
  quietly connecting directly.
* **DNS lookups by scan modules** still use the server's resolver. The subject's name servers see
  the resolver's address, so deployments should use a shared public resolver (see
  `docs/DEPLOYMENT.md`).

## 7. What a reviewer can check

* `argus/core/settings.py`: `EgressRoute`.
* `argus/evidence/guard_proxy.py`: the guard proxy and `tunnel()`, which chains through the route
  with HTTP CONNECT.
* `argus/evidence/capture.py`: one routed guard proxy for both the page fetch and the browser; the
  neutral identity.
* `argus/core/engine.py` and `argus/core/http.py`: routed scans.
* `argus/api/opsec_routes.py`: route listing, the route test, and the rules for anonymous cases.
* `tests/test_opsec.py`:
  * Tor routes never resolve names locally;
  * internal addresses never reach a route;
  * proxy credentials;
  * a failing route is not bypassed;
  * captures and scans go through the route with a neutral identity;
  * leak detection;
  * anonymous cases refuse direct work;
  * a real browser through a route reports UTC, en-US and plain Chrome.
