# 24 — Breach & Dark-Web Exposure (Plain-English Guide)

> Purpose: explain how Argus watches for an organisation's credentials and name turning up in
> breaches, infostealer logs and on ransomware leak sites. It's useful for questions like:
> * "what is dark-web monitoring, really?"
> * "what's an infostealer?"
> * "how do you do this legally and ethically?"
> * "how do you handle staff personal data?"

## 1. Why this matters

Most intrusions don't start with an exploit. They start with **a valid login**: a password reused
from a breached website, or a session cookie stolen by malware. Two signals give that warning
earliest:

* **Infostealer logs.** Infostealer malware (RedLine, Lumma, Raccoon…) runs on someone's
  computer, often a personal laptop also used for work, and copies every password and session
  cookie the browser has saved. The bundles ("logs") are sold or traded in bulk. A stolen
  *session cookie* can bypass MFA, which makes these the most urgent finding in this area.
* **Ransomware leak sites.** Modern ransomware groups steal data before encrypting it, then post
  the victim's name on a "leak site" to pressure them into paying. Seeing your organisation there
  means an incident. Seeing a **supplier** there means your data may be in the stolen files.

Commercial "dark-web monitoring" products sell these signals. Argus now produces them, wired
into the same alerting, supplier and audit machinery as everything else.

## 2. What Argus checks

| Finding | Source | Severity |
|---|---|---|
| Staff credentials in **infostealer logs** | HIBP stealer logs | critical |
| Organisation named on a **ransomware leak site** | ransomware.live research feed | critical (recent, domain match) · high (name match only) · medium (over a year old) |
| The organisation itself **was breached** | HIBP breach catalogue | high (added this year) · medium |
| **Staff accounts in breaches** | HIBP domain search | high (passwords, added this year) · medium (passwords, older) · low (no passwords) |

Watched domains are checked daily. The **supplier register** (Phase 22) is swept automatically
for breaches and ransomware posts, so a supplier hit by ransomware raises an alert, and its row in
the register shows a "Ransomware post" flag.

## 3. Doing it legally and ethically

"Dark-web monitoring" can mean buying stolen data or lurking on criminal forums. Argus does
neither:

* **No visits to criminal infrastructure.** Leak sites are Tor hidden services run by criminals.
  Argus reads **ransomware.live**, a public research project that indexes their posts, never the
  sites themselves.
* **No stolen data.** Only metadata is collected: which address, which breach, which data
  *classes* ("Passwords", "Phone numbers"), when, and which websites stolen credentials were for.
  Never passwords, cookies or leaked files.
* **Authorisation is enforced by the source.** HIBP's domain search and stealer-log search only
  answer for domains the API key's owner has **proved they control** (by DNS record, meta tag or
  email). Argus can't be used to list another company's staff. Without that verification HIBP
  answers `403`, and Argus says plainly "verify the domain in your HIBP dashboard". The public
  sources (the breach catalogue, ransomware posts) describe organisations, not people.
* **Every watch records its basis** ("our corporate domain, monitored by the SOC") and who added
  it, in the audit log.

## 4. Staff addresses are personal data

Under the UK GDPR a work email address identifies a person, and "this person's account was in a
breach" is information about them. Argus follows data-protection principles by design:

* **Data minimisation** (Article 5(1)(c)): addresses are **masked everywhere by default**
  (`j•••e@acme.com`). That's enough for a security lead to see the scale ("5 accounts, 2 with
  passwords"), but not to identify anyone.
* **Revealing or exporting is a deliberate, audited act.** An analyst can show full addresses,
  or export a CSV to drive password resets. Either way the audit log records who did it and *how
  many* addresses were disclosed. Viewers can't do either.
* **Alerts never contain addresses.** Alerts travel to Slack, Teams, email and SIEMs, places
  with wider audiences and longer retention. They say "2 staff accounts in a new breach", and the
  addresses stay in Argus.
* **Storage limitation** (Article 5(1)(e)): findings closed for longer than the retention period
  (default 365 days) are deleted automatically.

## 5. Engineering decisions worth noting

* **Baseline, then news.** The first check of a domain finds years of history, and alerting on a
  2016 forum breach would teach people to ignore alerts. So the first check is a *baseline* that
  alerts only on serious findings (high or critical). After that, everything new is announced,
  grouped into **one alert per check**: "New exposure for Acme: named on the akira ransomware leak
  site; 1 staff account in infostealer logs".
* **Stable identity, no duplicates.** Each finding has a stable key (account + breach; group +
  victim + date), stored as a SHA-256 hash and unique per workspace. Re-seeing the same thing only
  updates "last seen".
* **The outbox again.** New findings, the alert and the alert's notifications are written in **one
  database transaction**, so a crash can't lose an alert or announce findings that weren't saved.
* **Each source fails alone.** The catalogue can time out while the domain search works. Every
  check records each source's status ("ok", "unavailable on this plan", "error: timed out"), and
  the page shows it. A source that's unavailable (no key, not on the plan) isn't counted as an
  error.
* **Name matching is labelled.** Ransomware groups sometimes post a company *name*, not a domain.
  An exact match on the normalised name (legal suffixes like "Ltd" and "Inc" removed) counts, but
  is marked "matched by name only: verify" and rated high rather than critical. "Acmeville
  Bakery" does not match "Acme". `notacme.com` does not match `acme.com`.
* **Several replicas, one check.** Watches are *claimed* with a conditional UPDATE, like monitors
  and report schedules, so each daily check runs exactly once in a cluster. HIBP's rate limit (10
  requests a minute on the entry plan) is respected by spacing calls.
* **Triage with accountability.** A finding can be marked *resolved* ("password reset, laptop
  re-imaged") or *risk accepted* ("shared mailbox, no login"), and reopened. Each change records
  who made it and why.

## 6. The demo

*Load demo* adds clearly fictional exposure for `acme-corp.example`:
* an infostealer infection;
* a post by the invented group "demolocker";
* breached accounts across three invented breaches.

It goes through the same rules as live data, and is never checked against the real sources.

## 7. What a reviewer can check

* `argus/intel/exposure.py`: the rules (severity, matching, masking, headlines).
* `argus/intel/breach_sources.py`: the HIBP and feed clients, with their error handling.
* `argus/intel/exposure_monitor.py`: the loop, baseline logic and privacy-safe alerts.
* `argus/storage/exposure_repo.py`: the deduplication, the single-transaction outbox, and purging.
* `tests/test_exposure.py`:
  * the rules;
  * the client against a local fake HIBP and feed;
  * baseline and new-finding alerts;
  * that alerts carry no addresses;
  * the supplier sweep;
  * masking, audited reveal and export;
  * triage, roles, workspace isolation and purging.
