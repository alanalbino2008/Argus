# 72 — Signed case reports

## Why

A case report (Phase 70) travels: to an editor, a lawyer, a client, a court. Months later someone
may ask: *is this the report Argus produced, and has anyone changed it since?* A hash in the audit
log answers that only for people with access to the Argus server. A signature answers it for
anyone holding the file.

## What it does

Every case report is signed with this installation's **report-signing key** (Ed25519):

* The report is still **one HTML file**. Two `<meta>` tags carry the public key and the signature;
  the footer names the key id (for example `7a5b-2880-b2fa-813b`) and explains how to check it.
* The signature covers the whole file (every name, date, hash and word) with only the signature
  itself left blank. **Any change, down to one character, breaks it.**

## Checking a report

| Where | How | Needs |
| --- | --- | --- |
| Argus | **Cases → Verify a report**, pick the file | An Argus account |
| Command line | `argus --verify-report report.html --report-key 7a5b-2880-b2fa-813b` | Argus installed |
| Python | `argus_client.verify_report("report.html", "7a5b-2880-b2fa-813b")` | `cryptography` only, offline |
| API | `POST /api/reports/verify` (multipart `file`) | An API key |

Three outcomes:

1. **Genuine**: unaltered, and signed by the key you trust (this server's, or the id you gave).
2. **Altered**: changed after it was signed, or not signed at all.
3. **Intact, other key**: unaltered since it was signed, but by a key that is not the one you trust:
   someone else's Argus, or a forgery re-signed with a new key.

## Whose key it is

The public key inside the report proves the file was not altered after signing. That *your
organisation* signed it is shown by the **key id**: publish it (on a letterhead, a website, in the
covering email) or let recipients read it from `GET /api/report-signing-key`, which is public.

## The key

* By default it is created on first use and stored in the database, **sealed with the server's
  encryption key** (`ARGUS_ENCRYPTION_KEY`); without one it is stored unsealed, with a warning.
  Backups include it, so a restored server keeps signing with the same key.
* `ARGUS_REPORT_SIGNING_KEY` (base64, 32 bytes) sets it explicitly: replicas and rebuilt servers then
  share one key, and it can live in a secrets manager.
* Downloads carry the key id in `X-Argus-Report-Key`, and the audit log records each report's key
  id and SHA-256, and every verification (`report.verify`).
