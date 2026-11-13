# 05 — Intelligence Features (Plain-English Guide)

> Purpose: explain how Argus turns raw findings into intelligence that security teams actually use.

## 1. MITRE ATT&CK mapping

**MITRE ATT&CK** is the industry's shared catalogue of attacker behaviour. Its first tactic,
**Reconnaissance (TA0043)**, describes exactly what Argus does: gathering information about a
target before an attack.

Argus maps findings two ways:

* **Exposure** — every finding is classified by the kind of intelligence it gives an attacker.
  An email address is *T1589.002 Email Addresses*; a TLS certificate is *T1596.003 Digital
  Certificates*; an open port from Shodan is *T1596.005 Scan Databases*. Each technique comes
  with practical **defensive guidance** ("enforce DMARC p=reject and train staff on phishing").
* **Emulation** — every module declares which adversary behaviour it reproduces, and whether it is
  **active** (it touches the target's own servers: the TLS and HTTP modules) or **passive** (it only
  queries third-party databases). Many bug bounty programmes only allow passive recon, so this
  distinction matters ethically and legally.

The **Navigator layer** export opens in MITRE's official
[ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) as a heat-map: the more
findings for a technique, the hotter its cell.

> **Interview line:** "I mapped Argus's output to MITRE ATT&CK so a report says not just *what*
> was found but *which reconnaissance techniques* the organisation is exposed to and how to reduce
> that exposure — turning OSINT into something a blue team can act on."

## 2. STIX 2.1 export

**STIX** is the OASIS standard language for sharing threat intelligence between tools (OpenCTI,
MISP, commercial platforms). Argus exports an investigation as a STIX *bundle*:

| Argus | STIX |
|---|---|
| domain, IP, email, ASN, certificate, software, URL, username | *Cyber-observable objects* (`domain-name`, `ipv4-addr`, …) |
| person / organisation | `identity` |
| CVE | `vulnerability` (linked to NVD) |
| ATT&CK technique | `attack-pattern` (linked to MITRE) |
| graph edge | `relationship` |
| the investigation | a `report` containing everything |

Two details worth mentioning:

* **Deterministic IDs.** STIX derives an observable's ID from its value, so `93.184.216.34`
  always gets the same ID. That's how platforms recognise the same IP across different reports.
* **TLP:AMBER marking.** The *Traffic Light Protocol* tells recipients how widely they may share
  something. An OSINT dossier about a target is sensitive, so exports default to AMBER (limited
  disclosure).

Every export is validated by the official `stix2` library in strict mode in the tests.

## 3. Optional API-key modules

| Module | Adds | Key setting |
|---|---|---|
| VirusTotal | how many security vendors flag a domain/IP as malicious | `ARGUS_VIRUSTOTAL_API_KEY` |
| Have I Been Pwned | which public data breaches contained an email address | `ARGUS_HIBP_API_KEY` |
| Shodan host | product **and version** behind every open port, CVEs, hostnames | `ARGUS_SHODAN_API_KEY` |

* **Off without a key.** Unconfigured modules don't load; the API shows what each one needs.
* **Respects quotas.** VirusTotal's free tier allows 4 requests/minute, so Argus spaces its
  requests 15 seconds apart *for that host only* — other modules carry on at full speed.
* **Keys never leak.** HTTP error messages often include the request URL, and Shodan takes its
  key *in* the URL. Every key a module reads is registered and **redacted** from anything Argus
  records or displays. A test proves a crashing module's key never reaches the investigation log.
* **Privacy.** Internal IPs are never sent to third-party APIs, and HIBP returns breach
  *metadata* only — never credentials.

## 4. Plugin system

Other developers can add collectors as separate Python packages (via *entry points*), without
changing Argus. Because a plugin is someone else's code running with the server's permissions,
the design is **secure by default**:

1. **Allowlist only** — installing a package does nothing until its name is in `ARGUS_PLUGINS`.
2. **Validated** — must be a real module, can't impersonate or replace a built-in module (e.g. a
   fake `dns_recon`), and may only declare real ATT&CK technique IDs.
3. **Isolated** — a broken plugin is reported at `GET /api/plugins`; Argus still starts.
4. **Audited** — every plugin loaded or rejected at startup is written to the audit log.

> **Interview line:** "Plugins are a supply-chain risk, so they're opt-in by explicit allowlist,
> validated so they can't shadow trusted modules, and recorded in the tamper-evident audit log."

## 5. Questions you might be asked

* **"What's the difference between ATT&CK and the Cyber Kill Chain?"** The kill chain is a
  high-level sequence of 7 phases; ATT&CK is a detailed, evidence-based catalogue of specific
  techniques within each tactic.
* **"Why STIX rather than just JSON?"** Interoperability: any STIX-aware platform can ingest and
  correlate it without custom code.
* **"What is TLP?"** A sharing label: CLEAR (public), GREEN (community), AMBER (limited, need-to-know),
  RED (named recipients only).
