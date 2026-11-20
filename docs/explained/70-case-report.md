# 70 — The case report, in one file

## Why

A case ends up in someone else's hands: an editor deciding whether to publish, a lawyer, a client,
a regulator, a court, or simply the archive. They need to read it without an Argus account, often
years later, and they need to trust that what they read is what the investigator had.

The evidence bundle (ZIP) carries the files and lets anyone verify them. It is not something a
person reads, though. The case report is.

## What it does

**Case report** on a case downloads one HTML file:

| Section | What is in it |
| --- | --- |
| Header | Title, purpose, status, handling (anonymous or standard, restricted), tags, case id, who generated it and when |
| Figures | Entities, links, dated entries, evidence items, scans, notes |
| Summary | The case summary, as written |
| Network | A chart of the case's entities and links (the 150 most connected), the most connected entities, bridges between groups, and every link with its confidence and dates |
| Timeline | Every dated entry, oldest first: events, evidence, scans, and the facts inside the linked scans (registrations, certificates, breaches, accounts…) |
| Evidence | Per capture: where and when, by whom, the digest, each file's SHA-256, the RFC 3161 timestamp, the chain of custody, and the integrity check made at export |
| Scans, notes | What was scanned, by whom, and the investigators' notes |

## Safe to open

* **One file, nothing fetched.** Styles are inline and the chart is inline SVG. A
  Content-Security-Policy in the file forbids scripts and every outside request, so opening the
  report never tells anyone that it is being read, a subject's server included.
* **Nothing clickable leads to a subject.** Addresses of captured pages are shown as text, so a
  reader cannot visit a subject's site by accident.
* **Protected people stay unnamed**, as everywhere in Argus.
* It prints cleanly (the confidentiality banner repeats on every page) and reads on a phone.

## Provable

* The report's **SHA-256** is returned with the download (`X-Argus-Report-SHA256`) and recorded in
  the audit log (`case.report`), so a copy that turns up later can be shown to be the one Argus
  produced, by whom and when.
* Every capture listed gets a `reported` entry in its chain of custody.
* The evidence's integrity is **checked at export**: a file that changed after capture shows up in
  the report as an integrity problem, not silently.
* The files themselves are not embedded: they stay in the evidence bundle, whose hashes match the
  report's.

## API

```http
GET /api/cases/{id}/report.html
```

```python
open("report.html", "wb").write(client.case_report(case_id))
```

Viewers and up can download it; a restricted case stays restricted.
