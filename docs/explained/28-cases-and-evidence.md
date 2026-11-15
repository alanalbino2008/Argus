# 28 — Cases & Evidence Capture (Plain-English Guide)

> Purpose: explain how Argus supports journalists, investigators and independent researchers. It
> covers how a case holds a whole investigation, and how web pages are preserved so they can be
> relied on later. It's useful for questions like:
> * "how do you prove a web page said something?"
> * "what is chain of custody?"
> * "what is an RFC 3161 timestamp?"
> * "how do you capture a hostile page safely?"

## 1. Why this matters

People investigating on their own (journalists, fraud and due-diligence investigators, researchers)
work differently from a company security team. They follow **people, accounts and events**, and
everything they find has to **stand up later**: to an editor, a lawyer, a court or a regulator.

Web pages change and disappear, often as soon as someone realises they are being looked at. A
screenshot taken on a laptop proves little: anyone can edit one. What's needed is preservation
that someone else can check. Professional tools for this are expensive. Argus now does it, inside
the same place as the rest of the investigation.

## 2. Cases

A **case** is one story or inquiry. It holds:

* **Purpose**: required, and recorded with the case and in the audit log.
* **People and entities**: people, organisations, usernames, accounts, emails, phones, domains,
  IPs, **addresses**, locations, vehicles, documents. Each has free-form details such as home
  address, employer or relatives. Inside a case, **everything is shown in full**: investigators
  need the whole picture.
* **Links** between entities ("Jane Roe *uses* jane@…"), each marked *confirmed*, *likely* or
  *possible*, so certainty never gets lost along the way.
* **A timeline** of dated events and every capture, in order.
* **Notes**: leads, hypotheses, what was checked.
* **Linked scans**: any Argus investigation that belongs to the case.
* **Evidence**: see below.

Anything on the investigation graph can be sent into a case with its details (**+ Case** in the
detail panel).

**Restricted cases** can be opened only by their owner and the people they name. There is **no
administrator exception**: a journalist protecting a source needs the case to be invisible even to
colleagues who run the system. To anyone else a restricted case answers "not found", exactly as if
it didn't exist.

**Accountability instead of hiding.** Rather than masking information, Argus makes every use
traceable. Every case view, change, capture, download and export is written to the tamper-evident
audit log. Combined with the operator controlling who gets an account, this is how professional
investigation tools prevent misuse. Argus is not designed for, and must not be used for, profiling
children.

## 3. Capturing a web page

*Capture a page* makes Argus's **server** fetch the page, so the people being investigated never see
the investigator's own address or browser. It keeps:

| File | What it is |
|---|---|
| `page.html` | the server's response, byte for byte |
| `screenshot.png` | a **full-page** screenshot as a browser displayed it |
| `rendered.html` | the page after its scripts ran (what you'd see, not just what was sent) |
| `text.txt` | the readable text, for searching |
| `headers.json` | the HTTP status, headers and every redirect |

Files you already hold (a screenshot of a private chat, a document, a photo) can be **added as
evidence** and get the same treatment from the moment they're added.

## 4. Proving it later

Four layers, each checkable without trusting Argus:

1. **Fingerprints.** Every file's SHA-256 is recorded in a **manifest**, along with the URL, the
   time, the tool and anything the browser was refused. The **capture digest** is the SHA-256 of
   that manifest, so changing one byte of any file, or one detail of the record, changes the
   digest.
2. **Trusted timestamp (RFC 3161).** If a timestamp authority is configured, Argus sends it the
   digest (only the digest, never the content). The authority returns a signed statement that this
   exact digest existed at that moment. Anyone can check it later with
   `openssl ts -verify`, with no need to trust Argus or the investigator. This is the same
   mechanism used to timestamp signed documents and software.
3. **Chain of custody.** Every action on a piece of evidence (captured, viewed, downloaded,
   exported, verified) is recorded. Each entry's hash includes the hash of the one before it, so
   deleting or editing an entry breaks every entry after it.
4. **Verify.** One click recomputes every file's fingerprint, the manifest digest and the whole
   custody chain, and says exactly what doesn't match. The tests change a single file, and then a
   single custody entry, and check that both are caught.

**The evidence bundle** exports a case as a ZIP:
* the case, notes, people, links and timeline;
* each capture's files, manifest, custody log and timestamp;
* `SHA256SUMS`;
* a README explaining in plain words how to check each layer.

`sha256sum -c SHA256SUMS` proves nothing changed after export.

## 5. Capturing safely: hostile pages

The page being captured is written by the people being investigated, and may be hostile. Three
protections:

* **No server-side request forgery.** A page can ask the browser to load
  `http://169.254.169.254/…` (the cloud metadata service that hands out credentials), and the
  screenshot would show the answer. So the capture browser's only route out is a small **guard
  proxy** inside Argus:
  * it resolves every host name itself and allows only public addresses;
  * it connects to the address it checked, so a DNS answer that changes in between (DNS rebinding)
    can't get through;
  * it refuses everything else.

  Refused requests are listed in the capture's record. A test serves a page that loads the metadata
  address and checks it is refused while the page is still captured.
* **Pages can't stall the capture.** A page can freeze a headless browser with a pop-up
  (`alert()`), which a test found. Argus drives the browser through its DevTools Protocol,
  dismisses pop-ups automatically, and notes in the record that it did.
* **Captured content never runs inside Argus.** Captured HTML served from Argus's own address would
  run with the investigator's logged-in session. So HTML and every non-image file are only ever
  *downloaded*, with a `sandbox` security policy, and SVG files (which can contain script) are never
  shown as images.

**Privacy of the investigator.** Argus prefers Chrome's *headless shell*, which has no Google
services. Full Chrome contacts Google in the background even with those services switched off,
which would tell Google when and from where someone is investigating.

To hide the **server** too, and send captures through Tor or a VPN, see
[29 — Investigator safety](29-investigator-safety.md).

## 6. What a reviewer can check

* `argus/evidence/guard_proxy.py`: the egress guard for the capture browser.
* `argus/evidence/capture.py`: fetching, the DevTools-driven browser, text extraction, manifests
  and RFC 3161 requests (DER encoded by hand).
* `argus/storage/case_repo.py`: restricted visibility, the hash-chained custody log and
  verification.
* `argus/evidence/bundle.py`: the self-verifying export.
* `tests/test_cases.py`:
  * the proxy refusing internal addresses;
  * redirects to internal addresses refused;
  * a real browser capture of a hostile page (pop-up and metadata request);
  * timestamps;
  * restricted cases;
  * tamper detection;
  * the bundle's sums;
  * hostile files never shown inline.
