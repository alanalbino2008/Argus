# 37 — Playbooks (Plain-English Guide)

> Purpose: explain what playbooks do, what each one covers, and how they stay safe and
> accountable. Useful for questions like:
> * "what does Argus do when I give it a company name?"
> * "can it run on its own without me forgetting a step?"
> * "how do I know what a playbook did, and on whose behalf?"

## 1. Why this matters

Experienced investigators follow the same routine every time. A company means:

1. look it up in the register;
2. find its directors and owners;
3. check each one against the sanctions lists and the leaks;
4. preserve the register page;
5. write down what stands out.

It's easy to skip a step when busy, and newer investigators don't know the routine yet.

A **playbook** runs the whole routine from one starting point, inside a case, the same way every
time. Each step is recorded.

## 2. The playbooks

| Playbook | Starts from | What it does |
|---|---|---|
| **Company due diligence** | a company name | registers, directors and owners (UK Companies House), parent companies (GLEIF), US filings (SEC), offshore leaks, and sanctions checks for everyone found; preserves the register entries |
| **Person background** | a full name | directorships and their companies, sanctions and leaks; name matches are only possibilities and are marked as such. Never for children |
| **Online identity** | a username | accounts on hundreds of sites, including likely variants (jane.roe, jane_roe…), with public profile details; preserves each profile found |
| **Email footprint** | an email address | its domain, data breaches it appears in, published keys, and the accounts behind its username |
| **Crypto trail** | a wallet address | where the money came from and went, exchanges and services, wallets probably owned by the same person, sanctioned counterparties |
| **Website background** | a website | who registered it and when, its history in the Wayback Machine, related and look-alike domains; preserves its home page |
| **Phone number** | a phone number | country, carrier and line type |

A playbook only uses the sources it can reach. A source that needs a key you haven't set (such as
Companies House) is left out, and the page says so before you start.

## 3. The steps

Every playbook is made of the same kinds of steps:

* **Scan**:
  * runs the playbook's sources over the starting point;
  * the scan is linked to the case and goes through the case's **route** (for example Tor);
  * in an **anonymous case** only passive sources run, which never touch the subject's own
    systems.
* **Preserve**:
  * captures the pages that matter (the register entry, the profiles found, the home page) as
    evidence;
  * each capture has fingerprints, a trusted timestamp where set up, and a chain of custody.
* **Findings**:
  * picks out what stands out and writes it to the case as a **note**;
  * the most serious findings come first (section 4).
* **AI briefing** (optional):
  * the AI analyst reads the whole case, including the playbook's findings, and briefs you;
  * it only runs if you tick the box, which tells you the case material will be sent to
    Anthropic.

One step failing never stops the others. If the capture browser isn't installed, for example, the
preserve step says so and the findings are still written.

## 4. What stands out

Findings are sorted into three groups:

* **Needs attention**:
  * a possible sanctions match;
  * a sanctioned wallet;
  * a wallet that dealt with a sanctioned one.
* **Worth checking**:
  * a name in the Offshore Leaks;
  * an email in a data breach;
  * wallets probably owned by the same person;
  * a sanctions match that is *probably a different person*. When the register says the director
    was born in 1980 and the listed person in 1950, the match is moved down here and the reason is
    shown.
* **Also found**:
  * directors and owners, and how they control the company;
  * accounts found;
  * names with no exact match in the register, with the closest ones.

Each finding about a person, company, account or wallet can be ticked and added to the case as an
entity. Nothing is added without your choice, except:

* the starting point itself;
* the findings note, which says plainly that name matches are possibilities, not identifications;
* when nothing stood out, a reminder that this isn't proof: the sources are incomplete.

## 5. Safe and accountable

* **A purpose every time.** Starting a playbook needs the same confirmation as a scan. The audit
  log records who started it, on what, with the case's purpose.
* **Everything it does is recorded:** each scan, each page preserved and each AI briefing, each
  one marked with the playbook run it belongs to.
* **The case's safety settings apply:** its route, and passive-only sources for anonymous cases.
* **One at a time.** A case runs one playbook at a time, and closed cases run none.
* **You can stop it.** A scan already running finishes, and nothing after it starts.
* **Server restarts.** A run left unfinished by a restart is marked *interrupted*, never left
  "running" forever. In a cluster, a server only marks its own runs.
* **Fair use of the server.** Playbook scans wait their turn under the server's limit on
  simultaneous scans.

## 6. What a reviewer can check

* `argus/intel/playbooks.py`:
  * the catalogue of playbooks and their steps;
  * what stands out (`highlights`);
  * which pages are preserved (`capture_urls`);
  * the findings note.
* `argus/api/playbook_routes.py`: the checks at start, the background run, and each step.
* `argus/storage/playbook_repo.py` and migration `0020`: how runs are saved and marked
  interrupted.
* `argus/web/js/views/playbooks.js`: the Playbooks tab.
* `tests/test_playbooks.py`:
  * every playbook names real sources that suit its starting point;
  * what stands out, including namesakes moved down;
  * crypto findings;
  * the pages preserved;
  * a full run in a case (scan, capture, findings note, audit);
  * a failed capture not stopping the run;
  * the checks at start (unknown playbook, wrong kind of starting point, a mistyped wallet,
    purpose not confirmed, briefing not confirmed);
  * one run at a time, stopping, and closed cases;
  * the AI briefing step;
  * interrupted runs in a cluster.
