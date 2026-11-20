# 66 — The facts inside a case's scans, on its timeline

## Why

The case timeline (phase 32) already held what the investigator added, account changes, evidence,
photo dates, and one line per scan. But a scan is full of *dates of its own*: when a domain was
registered, when a certificate was issued, when an account was created, when a company was set
up and who was appointed when. Those are often the heart of an investigation. A charity "founded
in 2010" whose domain was registered last month and whose director was appointed last week tells
its own story, and it was buried in entity details.

## What goes on the timeline

| Fact | From | Source named |
|---|---|---|
| Domain registered / last changed / expires | domain and sub-domain registration data | the RDAP registration record |
| Certificate valid from / until | certificates | the certificate itself |
| Data breach | breaches | the breach notification service |
| Account created | social profiles and usernames | the platform's public profile |
| Company incorporated / dissolved | organisations | the company register |
| Director appointed / resigned | person → company relations | the company register |
| Wallet's first / latest transaction | crypto wallets | the blockchain |
| Archived | URLs | the Internet Archive |
| Document written / last edited | public documents | the document's own metadata |
| PGP key created | emails | the PGP keyserver |
| End of life | software | endoflife.date |
| Added to CISA's exploited list | CVEs | CISA's KEV catalog |

Each entry says where its date comes from and which module found it, and offers **Show on graph**,
which opens the scan and selects the entity.

## What changed between scans

For consecutive scans of the same target in the case, Argus compares the two graphs (using the
same comparison as monitoring alerts) and adds:

> **9 new on acme-corp.example**: since the scan of 21 Oct 2026, appeared: 3 domain, 2 subdomain,
> 2 url, 1 breach, 1 port. acme-corp-login.example, …

> **1 gone from acme-corp.example**: disappeared: 1 port. Port 21 (FTP)

## Honest dates

- **Precision is kept.** Sources give "2019", "2019-06", "2019-06-14" or a full timestamp. A
  year is not "1 January 2019 at 00:00", so the timeline shows *year only*, *month only* or *date*
  instead of a clock time for those, and the CSV keeps the original value's precision.
- **Implausible dates are dropped.** Years before 1900 or after 2200 are placeholders, never
  events. So are bare numbers and text that isn't a date.
- **No double counting.** The same fact seen by several scans is one entry ("seen in 2 scans"),
  pointing at the latest scan that saw it.

## Limits

- The 20 most recent **finished** scans linked to the case are used (running scans are still
  changing). Graphs come from the read-only cache, and the work runs in a worker thread.
- At most 5,000 fact entries per case.
- `GET /api/cases/{id}/timeline?facts=false` returns the timeline without them.

Tests: `tests/test_fact_timeline.py`.
