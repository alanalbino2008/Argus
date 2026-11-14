# 16 — Client Reports (Plain-English Guide)

> Purpose: explain how Argus turns an investigation into a document a client can act on,
> and the security and privacy decisions behind it. It's useful for "how do you communicate
> risk to non-technical people?", "what is TLP?" and "how do you handle personal data?"
> questions.

## 1. What it produces

**Report** on any finished investigation produces a branded PDF:

| Section | For whom |
|---|---|
| Cover: target, client, issuer, date, **overall exposure rating**, classification | Everyone |
| **Executive summary**: plain-English findings, risk gauge, severity chart, change since the last scan | Executives |
| **Priority recommendations**: the first fix for each attack path, merged and ordered by urgency | Managers, owners |
| **Attack paths**: scenario, attack chain, MITRE ATT&CK techniques, evidence, step-by-step remediation | Engineers |
| Exposure indicators, people and social-engineering exposure (aggregated) | Security team |
| Asset inventory, ATT&CK reconnaissance coverage | Engineers |
| Scope, methodology, limitations, sources; severity and TLP definitions; how to verify the file | Auditors |

It has a contents page, PDF bookmarks, "Page X of Y" numbering and the classification on
every page. Each workspace sets its own **branding**: organisation name, accent colour, logo
and footer note.

## 2. Classification: the Traffic Light Protocol

Security reports describe weaknesses, so who may read them matters. Argus uses the industry
standard **FIRST TLP 2.0**: **RED** (named recipients only), **AMBER+STRICT** (the recipient's
organisation only), **AMBER** (their organisation and clients, need-to-know), **GREEN** (their
community) and **CLEAR**. The label is printed in the standard colours in the header and
footer of every page, and its meaning is spelled out on the cover.

## 3. Personal data: minimised by default

An attack-surface report often involves people: a leaked password belongs to someone, and a
phishing path starts with an employee's name. A report is a document that gets **forwarded**,
so under GDPR's data-minimisation principle it should carry no more personal data than its
purpose needs:

* People appear as **counts**: people identified, accounts linked, the inferred email format
  and published role mailboxes. They are never listed.
* Inside attack paths, identifiers are **pseudonymised**: names become *Person A*, *Person B*;
  emails become `d•••@acme.com`; usernames `d•••`; phone numbers keep their last two digits.
  The same person gets the same label throughout, so the paths still read correctly.
* When the client must act on specific accounts (for example, resetting a leaked password),
  an analyst can tick **Name the people in attack paths**. That choice is recorded in the
  audit log with the report.

The asset inventory never lists personal identifiers either.

## 4. Security of the generator

### 4.1 Untrusted text can't become markup

ReportLab, the PDF library, formats text with a small markup language. That language can do
more than formatting: `<img src="/etc/passwd">` makes it **read a local file**, and
`<a href="javascript:…">` creates a live link. Host names, page titles and attack-path titles
come from scanned websites, which an attacker may control. So every untrusted value is
escaped before it reaches the PDF (`argus/reports/pdf.py: esc`), including table-of-contents
entries, which are markup too. A test plants these payloads in a report and checks they
appear as literal text, with no file embedded and no link created.

### 4.2 Uploaded logos are re-encoded

A logo is an untrusted file that ends up in documents sent to clients
(`argus/reports/branding.py`):

* At most 1 MB and 4000 pixels per side. The size is checked **before** decoding, which stops
  **decompression bombs**: a tiny PNG can claim to be 30,000 × 30,000 pixels.
* PNG or JPEG only, judged by actually decoding the file, not by its name.
* **Re-encoded** to a fresh PNG, so EXIF/GPS metadata, hidden payloads and polyglot files never
  reach a report.

### 4.3 Other controls

* Only analysts and above can generate reports, rate-limited to 10 a minute per user, because
  rendering costs CPU. Rendering runs in a worker thread so the API stays responsive.
* Reports are scoped to the workspace like everything else: another workspace's investigation
  answers 404.
* Responses carry `Cache-Control: no-store`, so proxies and browsers don't keep copies.

## 5. Proving a report is genuine

A PDF can be edited: a finding deleted, a severity softened, a logo forged. So Argus records
the **SHA-256 fingerprint** of every file it issues, with the report reference, the issuer,
the date and the classification.

* **In the app**: *Settings → Verify a report*. The browser computes the fingerprint locally;
  the file itself is never uploaded.
* **Without an account**: the recipient runs `sha256sum report.pdf` and opens
  `https://<argus>/api/reports/verify/<fingerprint>`. This endpoint is deliberately public,
  because the person who needs to check a report is usually the client, not an Argus user.

  It reveals nothing to anyone without the exact file. The fingerprint is the only key, and
  2^256 possible values can't be guessed or enumerated. It is also rate-limited per address.

Changing a single bit gives a completely different fingerprint, which the registry doesn't
know, so a tampered copy is reported as **not verified**. Generating a report is also
recorded in the audit log with its fingerprint.

## 6. Interview talking points

* "The report is generated **server-side** from the same analysis engine, so the document
  and the app never disagree, and automation can request reports through the API."
* "I treated **text from the internet as hostile, even in a PDF**: the renderer's markup can
  read local files, so everything untrusted is escaped, and a test proves it."
* "Personal data is **pseudonymised by default** with an audited opt-in: data minimisation
  applied to a document that will be forwarded."
* "Every report has a **registered SHA-256 fingerprint** and a public verification endpoint,
  which gives integrity checks to recipients who have no account."
* "Logos go through **decompression-bomb checks and re-encoding**: the standard defence for
  user-uploaded images."
