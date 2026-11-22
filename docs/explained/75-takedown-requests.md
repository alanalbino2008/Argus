# 75 — Takedown requests

## Why

Finding a phishing domain (Phase 71) and knowing it is live (Phase 74) only matters if it then goes
away. Two companies can make that happen: the domain's **registrar**, who can suspend the name, and
its **hosting provider**, who can remove the site. Both have abuse desks. Getting a takedown is mostly
about sending the right people a clear report with evidence, then following up.

## What it does

On any lookalike in **Monitoring → Brand watch**, **Report abuse**:

1. **Finds who to tell, in RDAP** (the successor of WHOIS): the domain's registrar, its IANA id and
   its abuse email; and, for each address the domain points to, the network's owner and abuse email.
   RDAP questions go to the registries (via rdap.org), never to the lookalike itself.
2. **Drafts the report**: what the domain imitates and how; when it got its first certificate (with a
   link to the certificate); the triage evidence (it serves your favicon, copies your page title,
   shows a password field, has mail servers); its addresses and host names; the registrar and host.
3. **You review and send it** from your own mailbox: **Open in email** fills in recipients, subject
   and text; **Copy text** copies it. Abuse desks reply to the sender, and some want a person to
   answer questions, so Argus never emails third parties on your behalf. The signature is a
   placeholder for your details.
4. **Mark as reported.**

## Following it up

Every run of the brand watch re-checks domains with an open takedown, whatever else it checks:

* the name **stops resolving** (the registrar suspended it): **Taken down**;
* with website checks on, the site is **gone on two runs in a row** (no answer, 404, 410, 451):
  **Taken down**. One failed visit is not enough: sites flap.

A low-severity alert says what went down, and the takedown keeps its history: drafted, reported,
checks, down or closed, with who did what and when. A takedown can also be **closed** by hand (the
provider refused, your legal team handles it, it was a false alarm).

## Access

Analysts draft, report and close takedowns; viewers see them; other teams never do. Every step is in
the audit log (`takedown.draft`, `takedown.reported`, `takedown.close`).

## API

```http
POST /api/brand-watches/{id}/takedowns                    {"domain": "acme-login.com", "organisation": "Acme plc"}
POST /api/brand-watches/{id}/takedowns/{domain}/reported
POST /api/brand-watches/{id}/takedowns/{domain}/close     {"reason": "Handled by legal"}
```

Takedowns (status, contacts, draft, history) are included in `GET /api/brand-watches`.
