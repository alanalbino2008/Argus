# 118. Closing the gaps

## Imported data on the timeline and in the graph

* The case **Timeline** shows, for every number, address or counterparty in an import that the case
  already holds, the **first and last** time it appears ("First of 3 in Call records: +447700900123
  (known about Jane Doe)"), labelled *Imported data*.
* A person's **Graph** shows their known numbers and addresses as they appear in imported data
  ("+447700900123: 3 in cdr.csv"), linked to the known detail.

## Mobile cells on the map

For imported call records (or UFDR extractions) whose cells are given as **MCC-MNC-LAC-CI** (a cell
global identity, for example `234-15-1001-501`), **Place the cells on the map** (Data tab) looks up
each cell's approximate area in **OpenCellID** (`ARGUS_OPENCELLID_API_KEY`, free) through the case's
route.

* Each cell becomes a place on the case map, with its range, how often it was used and when.
* A cell covers an area, often hundreds of metres or more, never an address.
* Up to 50 cells per import (the most used); cells already on the map are skipped; each placement is
  audited.

## PDF bank statements

Statements can now be imported as PDFs (when the PDF has text; a scanned statement does not). Lines
starting with a date and ending in an amount (and usually the balance) become transactions. With a
balance, money in or out follows how the balance moved; otherwise the wording decides. Every
transaction read from a PDF is marked "read from a PDF: check against the original".

**XRY and Oxygen**: their native report formats are not read. Use their CSV or XLSX exports (contacts,
calls), which are. Native readers can be added from sample exports.

## Accounts whose websites share an analytics ID

For every candidate account that links to a website, the website's archived home page is read
(`site_trackers`, from the Internet Archive, never the site) for analytics, advertising and
tag-manager IDs (Google Analytics, Tag Manager, AdSense, Meta pixel). Two accounts whose websites share
an ID are grouped as one owner (one tracking account, one operator). An open candidate sharing an ID
with a confirmed account scores higher.

## Preserving likely candidates

**Preserve likely candidates' pages after each search**, on a person's card (`PUT .../options`
`{"capture_likely": true}`), preserves the pages of up to 10 new *likely* candidates after each search,
before anyone confirms them. They are noted "Captured as a likely match … (not confirmed)". Off by
default.

## Every view audited

Opening a person's graph, timeline, connected people, groups and dossier is now recorded
(`subject.view_graph`, `subject.view_timeline`, `subject.view_associates`, `subject.view_groups`,
`subject.view_dossier`), as are option changes (`subject.options`), alongside the existing case and
person views, imports and their readings.
