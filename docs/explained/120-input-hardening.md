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

All of these are covered by regression tests (`tests/test_import_hardening.py`).
