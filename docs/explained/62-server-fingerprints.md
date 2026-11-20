# 62 — Server fingerprints: JARM, HASSH and certificates

## Why fingerprint servers

Domains, IPs and hosting change all the time; *how a server is configured* rarely does. Threat
hunters cluster attacker infrastructure by fingerprints that survive moving to a new IP. The
same goes for an organisation's estate, which is usually built from a few templates:

| Fingerprint | What it captures | Indexed by |
|---|---|---|
| **JARM** | How the TLS stack answers ten unusual handshakes | Shodan `ssl.jarm:`, Censys `services.jarm.fingerprint:` |
| **HASSH-server** | The SSH server's algorithm preferences | Shodan `ssh.hassh:` |
| **Certificate** | The exact certificate (SHA-1 / SHA-256) | Shodan `ssl.cert.fingerprint:`, Censys `services.tls.certificates.leaf_data.fingerprint:` |
| **Favicon** (Phase 60) | The site's icon | Shodan, FOFA, ZoomEye, Censys |

In Argus each fingerprint is a node, keyed by its hash. Every host that shares it links to the
same node, in one scan and across scans, so `degree>=2` finds the clusters:

```text
(category:jarm OR category:hassh) degree>=2
category:jarm jarm:29d2ad00041d08c00042d00028d3fd5dd001f7b765d0c5525a0c12d31f7a8f <-[USES_TECH]- *
```

## JARM

`argus/intel/jarm.py`, after Salesforce's 2020 reference:

1. Ten ClientHellos, each varying the TLS version (1.1 / 1.2 / 1.3), the cipher list (all, or no
   TLS 1.3 ciphers), the cipher order (forward, reverse, top half, bottom half, middle out),
   GREASE, a common or rare ALPN list, and the extension order.
2. Each reply is read as `cipher|version|ALPN|extension types`. An alert, a reset or silence
   counts as an empty answer.
3. The fingerprint is 30 characters for the ten cipher/version choices, then the first 32 hex
   characters of the SHA-256 of all the ALPNs and extension lists. All zeros means no TLS answer.

**Verification.** On five live OpenSSL servers (RSA, EC, TLS 1.2 only, a single cipher, ALPN with
server preference), Argus and pyjarm gave identical hashes. Each configuration gave a different
one. The tests pin a hash computed by pyjarm's hasher and check stability and discrimination on
live local servers.

**Differences from pyjarm, which Argus deliberately avoids:** pyjarm returns all zeros when *any*
one probe's connection is reset (common: servers reset TLS 1.1 attempts), and its ALPN list merges
`spdy/3` and `h2` into one entry, which changes reversed and middle-out orders. Argus follows the
original reference in both.

Probes run one after another (ten short connections) on port 443 of each domain and sub-domain,
and on ports 443, 4443, 8443, 9443 and 10443 found by other modules.

## HASSH-server

`argus/intel/ssh_fingerprint.py`, after Salesforce's 2018 HASSH:

1. Connect and read the server's identification line (`SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6`).
   Lines before it are allowed, as RFC 4253 permits.
2. Send our identification, then read the server's first binary packet, `SSH_MSG_KEXINIT`, which
   is still unencrypted.
3. `hasshServer = md5("kex;encryption s→c;mac s→c;compression s→c")`.
4. Disconnect. No key exchange happens and nothing is authenticated, so there are no failed-login
   log lines.

The fingerprint is computed from the algorithm lists **as sent**. Servers protected against
Terrapin advertise `kex-strict-s-v00@openssh.com` there, which correctly distinguishes them from
unpatched builds. It runs only on ports other modules found and identified as SSH (22, 2222,
22222 or `service_guess: SSH`), never by blind port probing. The software and version become a
technology entity (`OpenSSH 7.4`).

## Certificates

Certificates were already keyed by SHA-256, so hosts sharing one were linked. They now also
carry their SHA-1 (the form Shodan's filter takes) and ready-made Shodan and Censys searches for
every other server presenting the same certificate.

## In the interface

One panel serves favicons, JARMs, HASSHes and certificates. It shows what the fingerprint means,
how many hosts in this graph share it, its facts, and searches with Copy buttons. The searches
are pasted by the analyst. Argus never queries Shodan or Censys with them, so those services see
the analyst's query, not the target.

## Limits and safety

- **A lead, not proof.** Popular stacks share fingerprints with millions of unrelated servers (a
  CDN's TLS, a distribution's stock OpenSSH). Shared-fingerprint links therefore carry confidence
  0.5. The rarer the fingerprint, the stronger the link.
- **Active and direct.** Both modules contact the target's servers with raw sockets, so
  passive-only scans skip them, and so do routed scans (Tor/VPN), whose route they couldn't use.
  They resolve names first and connect only to vetted public addresses. A name resolving to a
  private address is never contacted.
- Third parties' assets (`out_of_scope`) are never fingerprinted.

Tests: `tests/test_server_fingerprints.py`.
