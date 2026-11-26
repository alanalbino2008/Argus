# 119. Breach intelligence, without storing passwords

A person's email addresses, usernames and phone numbers often appear in data breaches. For an
investigator that is lawful, useful evidence: it shows exposure, and **password reuse** is one of the
strongest ways to tie two accounts to one person. Argus adds this on the People tab, designed so it
**never stores a plaintext password**.

## What Argus keeps

For each exposure it keeps only:

* the **breach** (name, date, and, with HIBP, the kinds of data it leaked);
* the **identifier** (email, username or phone);
* a **masked** password (`s•••••3` — first and last character and the length), to recognise a match by eye;
* a **SHA-256 hash** of the password, for the reuse correlation.

The plaintext is turned into the mask and hash the instant a record is read from the provider, and then
dropped. It is never written to the database, the dossier or a report.

## Password reuse

If the same password (by hash) sits behind two of the person's identifiers, or behind a candidate and a
known account, Argus flags it. A candidate that **reuses a breached password with a known account** gains
that as an agreement in its score — a strong, specific link. Reused-password groups are listed on the
person's **Breaches & reused passwords** panel, and breaches appear on the person's timeline.

## Providers

Set `ARGUS_BREACH_PROVIDER`:

* **hibp** (`ARGUS_HIBP_API_KEY`): which breaches an email is in, and what each exposed. No password, no
  hash, so no reuse correlation and nothing to reveal.
* **custom** (`ARGUS_BREACH_PROVIDER_URL`, `ARGUS_BREACH_PROVIDER_API_KEY`): any provider that answers a
  `query` with JSON records (the DeHashed / LeakCheck shape). This enables the masked password, the reuse
  hash and the gated reveal.

Both run from the server, through the case's route (an anonymous case uses its anonymous route); nothing
reaches the person. Off by default. At most `ARGUS_BREACH_LOOKUPS_MAX` look-ups per person.

## Revealing a plaintext password — gated

A plaintext password is a working credential, so revealing one is deliberately hard. A single reveal
(`POST .../subjects/{id}/breaches/reveal`) is allowed only when:

1. a **custom** provider is configured (HIBP cannot reveal);
2. the **case records its legal authorisation** (warrant, order or ticket);
3. a **reason** is given, and recorded;
4. a **second administrator approves** it, where the workspace protects `breach.reveal` (two-person approval);
5. the reveal is **audited**, with the reason and the authorisation.

The plaintext is then re-fetched live from the provider, shown once, and never stored. It is never in
bulk, the default view, the dossier or a report. Argus does not test credentials or sign in anywhere.
