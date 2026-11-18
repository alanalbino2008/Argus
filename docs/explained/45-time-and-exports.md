# 45 — Relationships Over Time, and Exports (Plain-English Guide)

> Purpose: explain the link chart's time slider, and the pictures and PDFs Argus produces of a
> case's network and of a person's profile. Useful for questions like:
> * "who was connected to whom in 2019?"
> * "can I give my editor or the court a copy of the chart?"
> * "what does the PDF say, and what does it leave out?"

## 1. Relationships over time

Networks change: directors resign, partners split up, money starts flowing. When relationships
have start and end dates, the link chart's **time slider** shows the network as it stood in any
year:

* a relationship **appears** in the year it began and **disappears** after the year it ended;
* people with no relationship that year **fade**;
* **Play** steps through the years, one a second, so you can watch the network form;
* relationships with **no dates** can be shown (the default) or hidden.

Dates can be a year ("2016"), a month ("2016-03") or a day. Relationships added from scans carry
the company register's appointment and resignation dates, so company networks have a timeline
without any typing.

## 2. Exports

| Export | What it contains |
|---|---|
| **Picture** (PNG) | the link chart as it looks now, at high resolution |
| **Network PDF** | the chart as on screen, the most connected people, the go-betweens, the groups, every relationship (kind, how sure, when, how it was found) and who isn't connected yet. With the slider set, the network as it stood in that year |
| **Profile PDF** | everything in a person's or organisation's profile: details, relationships, accounts and contacts, places, what scans found, the timeline, and every note and document that names them, with the passages |

## 3. Safeguards in every PDF

* **Marked on every page** *CONFIDENTIAL: contains personal data*, with the case, the time it was
  generated and page numbers.
* **Leads aren't presented as facts.** Each PDF says that relationships marked likely or
  possible, and matches on a name alone, need checking against their sources.
* **Protected people are never named.** Children and anyone else marked protected appear only as
  "Protected person", and have no profile PDF.
* **Recorded in the audit log.** Every export is logged: who made it, of which case, and how big
  it was.
* **The chart picture is cleaned.** The browser sends the chart as a picture. Argus checks it is
  a real PNG of a sensible size and redraws it cleanly, so nothing else rides along into the
  document.

## 4. What a reviewer can check

* `argus/intel/relationships.py` (`edges_at`): which relationships held during a year, month or
  day.
* `argus/reports/case_pdf.py`:
  * the network and profile PDFs;
  * the confidentiality marking;
  * the caveat;
  * cleaning the chart picture (`clean_chart`).
* `argus/api/network_routes.py` and `argus/api/people_routes.py`: the export endpoints and their
  audit entries.
* `argus/web/js/views/casechart.js`: the slider, Play, Picture and PDF report; `profile.js`: the
  profile PDF button.
* `tests/test_case_exports.py`:
  * relationships on given dates, including partial dates;
  * the network PDF with the chart, as of a year;
  * bad pictures and dates refused;
  * the profile PDF;
  * protected people never named;
  * the audit entries.
