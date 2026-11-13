# 06 — The Attack Path Engine (Argus's Signature Capability)

> Purpose: explain the feature that makes Argus different from other OSINT tools.

## 1. The idea in one sentence

Most OSINT tools give you a **list** of findings; attackers think in **chains**. Argus connects
findings into realistic attack scenarios, ranks them, and tells you which one to fix first.

## 2. An example (from the built-in demo)

> *Dana Whitfield's work email appears in the FitTrackr breach, which exposed passwords.
> Attackers replay leaked passwords against company systems (credential stuffing). Because this is
> a corporate address, a hit could mean access to company systems.*
>
> **Route:** T1589.001 Credentials *(Reconnaissance)* → T1110.004 Credential Stuffing
> *(Credential Access)* → T1078 Valid Accounts *(Initial Access)* — **Risk 80, critical**

Each finding alone ("an email address", "a breach") looks minor. Connected, they're the most
likely way into the company.

## 3. How it works

The engine runs nine **rules** over the intelligence graph. Each rule describes one well-known
attack pattern and looks for the evidence it needs:

| Rule | Evidence it looks for | Leads to |
|---|---|---|
| Credential exposure | email ↔ breach (with passwords?) ↔ person | Credential stuffing → valid accounts |
| Spoofable email domain | domain with DMARC *missing* or *p=none*, plus known staff | Phishing |
| Exploitable public service | hostname → IP → service → reported CVE | Exploit public-facing application |
| Exposed sensitive service | RDP, SMB, Redis, databases… open to the internet | External remote services |
| Identity correlation | handle → several platforms → real email/name | Spear-phishing pretext |
| TLS interception | expired or self-signed certificate | Adversary-in-the-middle |
| Subdomain takeover candidate | CNAME to a claimable hosting provider | Compromise infrastructure |
| Malicious reputation | security vendors flag the asset | Existing compromise / abuse |
| Web information leak | version banners + weak security headers | Drive-by compromise |

**Scoring:** `risk = impact (1–5) ÷ 5 × likelihood (0–1) × 100`, then
critical ≥ 70, high ≥ 45, medium ≥ 25, low below that. The UI shows the formula on hover.

**Evidence, not guesses.** "DMARC unknown" (the DNS lookup failed) is never treated as "DMARC
missing". To make that possible, the DNS module records explicit three-valued facts
(`present / missing / unknown`) on each domain. An engine that cries wolf gets ignored, so the
tests check the *silent* cases as carefully as the alerting ones.

**Why rules and not machine learning?** Every score can be explained line by line — to a client,
an auditor or an interviewer. Rules are also easy to extend: a new rule is one Python function.

## 4. In the interface

* **Attack Paths tab** — severity-coloured cards with the entity chain, a plain-English narrative,
  the ATT&CK route (each technique links to MITRE), evidence and remediation steps.
* **Show on graph** — everything else fades and the chain glows red on the graph.
* **Executive report** — a "Prioritised Attack Paths" section for decision-makers.
* **API** — `GET /api/investigation/{id}/paths`.

## 5. The demo investigation

`argus --load-demo` (or `POST /api/demo`) loads *acme-corp.example*, a fictional company that
triggers every rule. It only uses **reserved** identifiers — `.example` domains (RFC 2606) and
TEST-NET IP addresses (RFC 5737) — so no real person or organisation is implicated. A test
enforces this. It lets anyone evaluate Argus without scanning a real target.

## 6. Questions you might be asked

* **"How is this different from a vulnerability scanner?"** Scanners list issues per host; the
  engine reasons *across* identity, email, DNS and infrastructure data to find chains no single
  scanner sees.
* **"Isn't this BloodHound?"** Same philosophy — attack paths over a graph — but BloodHound maps
  *internal* Active Directory; Argus maps the *external* attack surface from public data.
* **"How do you avoid false positives?"** Rules require positive evidence, likelihood reflects
  uncertainty (e.g. takeover candidates are scored low until verified), and reports state that
  paths are assessments, not confirmed exploitation.
