# 10 — Deep Recon (Plain-English Guide)

> Purpose: explain how Argus finds information an organisation has forgotten about or never meant
> to publish — and how it does that *accurately* and *responsibly*. Useful for "what makes your
> OSINT tool different from running Sherlock?" and "how do you avoid false positives?".

## 1. The idea

Live websites and DNS show what an organisation looks like *today*. Attackers also look at what it
looked like *before*, what its staff published *elsewhere*, and what leaked *by accident*. Phase 10
adds those sources, plus the engineering that keeps a much larger result set trustworthy.

## 2. Username hunting at scale — without the false positives

Argus now checks a handle on **127 platforms** (developer, security, social and fediverse, creative,
gaming…). Sites are described as data in `argus/data/platforms.json`, the same idea as Sherlock's
`data.json`, so adding one is a line of JSON, and operators can add their own (e.g. an intranet wiki)
with `ARGUS_EXTRA_PLATFORMS_FILE`.

Big site lists have a well-known problem: some sites answer "200 OK" for *every* username (login
walls, rate-limit pages, bot challenges), producing confident-looking nonsense. Argus fixes this with
**self-calibration**: whenever a site reports a hit, Argus also asks it about a random 16-letter
handle nobody has registered. If the site claims *that* exists too, the site is unreliable for this
scan and its result is thrown away (and listed, so the analyst knows). It costs one extra request
per site *that reported a hit*, not per site.

Signatures also rot as websites change. `argus --check-platforms` tests every one against a known
real account and a random one; a weekly GitHub Actions job runs it and publishes a report. Running
it during development found two broken signatures (NPM now serves a bot challenge; PyPI answered 200
for any name) which were fixed — exactly the kind of drift the check exists to catch.

## 3. New sources

| Collector | Technique | Why it matters |
|---|---|---|
| `wayback` | Internet Archive CDX index of every captured URL | Forgotten sub-domains; once-public `.env`, `.git`, database dumps and backups; admin panels; API specs; documents; credentials in URLs (values redacted) |
| `document_metadata` | Reads author/editor, software, company and dates from archived PDFs and Office files (the **FOCA** technique) | Author fields often hold *internal account names* — the login format an attacker needs for password spraying — and exact software versions |
| `passive_dns` | Five free passive-DNS / crawl datasets | Hosts that never had a public certificate; every host records which sources saw it |
| `github_org` | Finds the organisation's GitHub org, **only if its profile points back to the domain**, and its public members | Staff handles, which are then hunted across 127 sites and enriched |
| `code_leaks` | GitHub code search for the domain + secret patterns (AWS/GitHub/Slack/Google/Stripe keys, private keys, connection strings, passwords) | Leaked credentials and internal hostnames. Needs `ARGUS_GITHUB_TOKEN` (GitHub requires sign-in for code search) |
| `pgp_keyserver` | Public PGP key index | One key = one owner, so it links a work address to a real name and personal addresses |
| `web_recon` *(active)* | `security.txt`, `robots.txt`, exposed files, contact pages | Security contacts; paths hidden from search engines; `.git`/`.env`/`server-status` **confirmed by their content**; published emails and phone numbers |
| `cloud_storage` *(active)* | Asks Amazon S3 and Google Cloud Storage about buckets named after the organisation | Whether anyone can *list* the files — a classic cause of large leaks |

## 4. Making more data more trustworthy

* **Corroboration.** When two modules independently find the same thing, its confidence rises
  (noisy-OR: `1 − (1 − a)(1 − b)`) and the graph shows *which* sources saw it.
* **Content-verified exposure.** A `.env` "found" only because a site returns 200 for every path would
  be a false alarm. Each exposed-file check looks for the file's real signature (e.g. `ref: refs/` for
  `.git/HEAD`).
* **Archived ≠ live.** Archive findings say so, score lower, and link to the archived copy.
* **Name matches are not ownership.** Anyone can create a bucket called `acme-backups`; such findings
  are marked *ownership unverified* with modest confidence.
* **No over-merging.** An organisation's GitHub account is linked to every member, so it is never
  allowed to merge them into one "person".

## 5. Email format inference

From staff whose name *and* work address are known (`Dana Whitfield` → `dana.whitfield@`), Argus
learns the format (`first.last`) and predicts the address of staff found without one — but only for
people linked to the organisation's own assets (its documents, GitHub org or domain), and always
labelled **inferred**. That is the same reasoning a phishing campaign uses, which is why defenders
should see it first.

## 6. New attack paths (14 rules)

* **Credentials leaked in public code** → *Unsecured Credentials* → *Valid Accounts* (critical).
* **Exposed sensitive file** — live (`.git`/`.env`: critical) or archived (lower: verify and rotate).
* **Publicly listable cloud storage** → *Data from Cloud Storage*.
* **Staff enumeration** — three or more harvested staff identities → *Password Spraying*.

## 7. Responsible by design

* **Passive-only mode** (`passive_only`, a checkbox, `--passive-only`) skips every module that touches
  the target's own systems, for bug-bounty programmes that forbid active testing. Monitors remember it.
* **Secrets are never stored**: only their type, a 4-character preview and length. Credential values in
  archived URLs and `.env` files are redacted. From `.env`, only variable *names* are kept.
* **Hostile files are expected**: documents are size-capped, zip members are checked before reading,
  and XML is parsed with `defusedxml` (no DTDs, no entity expansion, no external entities).
* **Out of scope on purpose**: dates of birth, ages, home addresses and payment handles are not
  collected. They don't describe an organisation's attack surface, and gathering them about private
  individuals is the territory of stalking and identity theft (and needs a lawful basis under UK GDPR).

## 8. How it is tested

`tests/test_deep_recon.py` replays realistic responses for every collector with no network: archive
classification and redaction, OOXML/ODF/PDF parsing including compressed PDF streams and UTF-16
strings, a zip bomb and an XXE payload being rejected, passive-DNS merging with a failing source,
the GitHub org verification, secret redaction, the PGP index format, soft-404 resistance in exposed-
file checks, phone normalisation, bucket states, corroboration maths and passive-only filtering.
