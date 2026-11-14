# 09 — People & Software Intelligence (Plain-English Guide)

> Purpose: explain how Argus goes from "we found a username" to "here is the person, what they
> expose and why it matters" — and from "the server says PHP/7.4.3" to "this is unsupported and
> attackers are exploiting it". Useful for "how does your OSINT tool handle people?" and "how do you
> prioritise vulnerabilities?" interview questions.

## 1. The problem

Older Argus versions *found* identifiers — an email in WHOIS, a GitHub account, a CVE on an IP —
but stopped there. A real investigator asks the next question every time:

* *Where did this account come from, and what does it say about its owner?*
* *Are these five fragments one person or five?*
* *Is this CVE theoretical, or are criminals using it this week?*

## 2. Following an account: `profile_enricher`

When a profile is found, Argus calls that platform's **official, public, unauthenticated API** —
never scraping behind a login, never guessing passwords — and records what the owner chose to
publish:

| Platform | API | Notable facts |
|---|---|---|
| GitHub | `api.github.com/users/…` | name, company, location, blog, join date, repos |
| GitLab | `/api/v4/users` | name, organisation, public email, Twitter/LinkedIn |
| Keybase | `user/lookup.json` | **cryptographic proofs** of other accounts and websites |
| Mastodon | `accounts/lookup` | bio, **`rel="me"` verified links** |
| Reddit, Hacker News, Dev.to, Docker Hub, Bluesky | public profile endpoints | bio, join date, linked accounts |

Facts become graph entities: a real-looking display name → `PERSON`; a declared location →
`LOCATION` (ATT&CK T1591.001); an employer → `ORGANIZATION`; a personal website → `DOMAIN`; an email
in a bio → `EMAIL`; and linked accounts → new `SOCIAL_PROFILE`s.

**Proof matters.** A Keybase proof or a Mastodon green tick means the platform verified that the
same person controls both accounts. Those links get confidence 0.95 and their handles are hunted in
turn. A link someone merely *typed* into a bio gets 0.6 and is not hunted.

## 3. Enrichment without runaway scans

Scans have a depth limit so they finish. But a CVE found at the last hop still deserves its
threat intelligence. Modules can declare `enrichment = True`: the engine runs them on entities **at**
the depth limit, and anything they discover is recorded but never expanded. The scan stays bounded,
and leaves are no longer blind spots.

## 4. Identity resolution: fragments → people

`argus/intel/identity.py` groups identity entities (people, usernames, emails, profiles, phones)
that are linked to each other, using a **union-find** (disjoint-set) structure — the same algorithm
used for network connectivity. Two deliberate rules stop false merges:

1. **Organisations, domains and locations are attributes, never bridges.** Otherwise everyone who
   works at Acme would collapse into one "person".
2. **Shared inboxes are not people.** `info@`, `security@`, `finance@` … are kept aside, and Argus
   no longer hunts "info" across social networks (that only ever found strangers).

Each **persona** gets a dossier: accounts with their profile facts, handles, emails, locations,
employer, websites, breaches, a **timeline** (joined GitHub 2014 → password in a 2023 breach), the
**exposures** that matter for social engineering, and the **attack paths** they appear in.

Every account is graded honestly:

| Grade | Meaning |
|---|---|
| **Verified** | The platform or a cryptographic proof confirms it (Keybase, Mastodon, Gravatar by email hash) |
| **Strong** | Collected with high confidence, not independently proven |
| **Possible** | The same handle exists there — it may belong to someone else |

## 5. Software and CVE intelligence: `software_intel`

| Question | Source | Example |
|---|---|---|
| Is this version still supported? | endoflife.date | PHP 7.4 — end-of-life since 28 Nov 2022 |
| Is this CVE exploited in the wild? | CISA KEV catalog | CVE-2024-21762 added 9 Feb 2024 |
| How likely is exploitation soon? | FIRST EPSS | 91.6% in the next 30 days |
| How severe is it? | NIST NVD | CVSS 9.8 Critical |

The KEV catalog is downloaded once per scan and shared by every CVE; NVD is rate-limited to its
documented 5 requests per 30 seconds.

This feeds prioritisation directly: an attack path through a **KEV-listed** CVE rises to likelihood
0.9 (0.95 with known ransomware use) and is titled *"Actively exploited vulnerabilities exposed"*;
a new **end-of-life software** rule explains that every future vulnerability in that version will
stay unpatched.

## 6. Privacy, ethics and OPSEC

* **Public data only**, via official APIs; rules of engagement (purpose + authorisation) still apply
  to every scan.
* **Viewing dossiers is audited** (`investigation.people` in the tamper-evident audit log), because
  aggregated personal data is sensitive even when each piece is public.
* **No remote avatars.** Loading a profile picture would make the analyst's browser contact the
  subject's platform and leak the analyst's IP address. Argus shows initials instead.
* Profile facts are labelled *self-declared*: a lead to verify, not a fact.

## 7. How it is tested

`tests/test_people_software.py` replays realistic API responses for every platform (no network),
including Keybase proofs becoming verified handles, Mastodon verified vs. claimed links, and
de-duplication. `tests/test_identity.py` checks that colleagues sharing an employer stay separate,
role inboxes never bridge people, and same-handle hits are only "possible". The engine test proves
enrichers run on leaves without expanding them.
