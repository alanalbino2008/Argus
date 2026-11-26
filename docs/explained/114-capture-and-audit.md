# 114. Preserving what is confirmed, and recording on what authority

## Confirmed accounts are captured at once

Confirming an account (**Theirs**) now preserves its page as evidence straight away, through the
case's route, before it can be changed or deleted. The capture is an ordinary piece of case evidence
(fingerprinted, timestamped if a timestamp authority is set, with its chain of custody), noted as
"Captured when confirmed as belonging to …". The candidate shows whether its page was preserved, or
why not (for example, an anonymous case without its route). A failed capture never undoes the
confirmation. Send `"capture": false` to confirm without capturing.

## WARC and PDF

Every web capture now also contains:

* **`page.warc`**: the capture in the web-archive standard (WARC 1.1, ISO 28500): the redirect chain,
  the server's response, and the screenshot, for replay tools (ReplayWeb.page, pywb) and archives. The
  body is the one received after decompression, so the content-encoding headers are dropped; every
  record carries a SHA-256 digest.
* **`page.pdf`**: the page printed by the headless browser (when one is installed).

Both are listed in the capture's manifest with their SHA-256, so they are covered by the capture digest
like every other file.

## The legal authorisation of a case

A case can record the legal authorisation its work rests on (a warrant, court order, ticket or
assessment reference). It is:

* encrypted at rest;
* shown on the case and in the case report;
* included in the audit details of the case's creation, of every person search, confirmation and
  automatic capture.

With `ARGUS_REQUIRE_CASE_AUTHORIZATION=true`, a case cannot be created without one.

## Opening a person is audited

Opening a person's card is now recorded (`subject.view`), as opening a case is (`case.view`).
