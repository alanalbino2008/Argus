# 120. Hardening the untrusted-file readers

The import, document and capture code reads files and web pages that an investigator does not control:
spreadsheets, ZIP-based formats (XLSX, UFDR, DOCX), PDFs, and the headers of fetched pages. This pass
closes several ways a crafted file or hostile site could waste memory, hang the server, or corrupt an
evidence file. None of it changes what a normal file produces.

## Spreadsheets (XLSX)

* **A cell addressed far to the right can no longer force a huge row.** A worksheet row is built only up
  to a fixed column cap (`MAX_COLS`), and a malformed cell reference (many letters) is skipped, so a tiny
  file cannot make Argus allocate a multi-gigabyte row.
* **A non-numeric shared-string index is treated as empty** instead of raising.

## ZIP-based formats (XLSX, UFDR, DOCX)

* **Decompression bombs are bounded on the real stream.** The amount Argus reads from a member is enforced
  while decompressing (`MAX_XML`, 64 MB), not taken from the size the archive declares — which a crafted
  file can understate to smuggle a huge member past a naive check.

## PDFs

* **Over-long lines are skipped** before the statement-line pattern runs, so a line of tens of thousands of
  characters cannot cause the regular expression to backtrack for a long time (a denial-of-service class).
* **Content streams are bounded in total**, not only per stream, when reading a document for text.

## WARC evidence

* **Captured response headers are stripped of carriage returns and newlines** before they are written into
  a WARC file. A header value containing a line break can no longer inject extra header lines or forge a
  record boundary in the evidence.

## Outbound fetches (SSRF)

The new sources that fetch a web address an investigator does not control — documents found by web
search, archived profiles and pages, a custom breach provider, OpenCellID — all go through Argus's
existing outbound guard: every request's host is checked, and the DNS resolver refuses private, loopback
and link-local addresses (including the cloud metadata address `169.254.169.254`), so a public URL that
redirects to an internal one is still blocked. This is covered by the existing SSRF tests
(`test_security`, `test_opsec`).

## Rate limits

The endpoints that trigger external look-ups or are sensitive now have their own per-caller limits, so a
single key cannot flood a provider or the server: breach look-ups (10/min), password reveals (6 per 5
min), data imports (12/min) and cell look-ups (4/min), alongside the existing scan and dossier limits.

## Covered by tests

Regression tests for the file readers are in `tests/test_import_hardening.py`; the rate limits in
`tests/test_breaches.py` and `tests/test_imports.py`.
