# Infostealer intelligence — the sites a person's logins unlock

Infostealer malware (RedLine, Raccoon, Lumma and their kin) quietly copies everything a victim's browser
has saved — every username, password and session cookie — and ships it to a marketplace. For an
investigator this is the richest single source on the dark web, because a stealer log does not just say
"this password leaked": it lists **the exact sites the person had saved logins for**. That reveals
accounts you did not know existed — a bank, a second email, a work portal, a forum — each a new lead.

Argus already surfaced infostealer infections for a **domain you own** (via Have I Been Pwned's
stealer-log endpoints). This phase makes that intelligence work **by identifier** — for a person in a
case, and for an email you watch — while keeping Argus's rule that **no plaintext is ever stored**.

## On a person (the People tab)

When you run a breach look-up on a subject, Argus now also reads infostealer logs for their email
addresses, and shows an **Infostealer infections** panel: the list of sites their captured credentials
unlock, the stealer family if known, and when the most recent infection was seen. Those sites are
**accounts the person holds** — treat each as a lead to confirm.

- With a **custom provider** (DeHashed/LeakCheck shape), any record that looks like a stealer log — it
  names a captured site and a stealer/malware family, or comes from a stealer dataset — is recognised,
  and its site, family, computer name and infection date are kept.
- With **Have I Been Pwned**, an email's `stealerlogsbyemail` result (the website domains its credentials
  unlock) is read where your plan includes stealer logs.

As everywhere in Argus's breach handling, the **plaintext password is dropped on read** — only a masked
form and a one-way hash are kept — so the infostealer panel is metadata only. Password reuse across a
known account and a stealer log still raises a candidate's score, exactly as before.

## On an email you watch (Exposure)

A **selector watch** (watch a term) whose selector is an **email address** now also checks infostealer
logs for it, raising a critical *"credentials captured by infostealer malware"* finding that lists the
unlocked sites — the same alerting, triage and export as any other exposure finding. This needs a
Have I Been Pwned key with the stealer-logs plan.

## What is kept, and what is not

| Kept (metadata) | Never kept |
|---|---|
| which identifier, which sites the logins unlock | the plaintext password |
| the stealer family, the computer/host name, the infection date | the session cookies or stolen files |
| a masked password and a one-way hash (for reuse correlation) | anything fetched from a criminal marketplace |

Argus does not buy, open or mirror stealer logs; it reads them only through the configured provider's
API, server-side and through the case's route. A single plaintext reveal remains a separate,
approval-gated, audited action.

This is the third step strengthening dark/deep-web coverage, after selector watches and the paste/leak
sources. Next: a ransomware-ecosystem intelligence hub.
