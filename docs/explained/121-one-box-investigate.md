# One box: start an investigation from a single detail

Most of the time an investigator starts with **one** thing: an email that came in a complaint, a
username from a marketplace listing, a phone number on a scam text, a link to a profile. The quickest
tools let you paste that one thing into a box and press go. Argus now does the same — without throwing
away the case, the legal purpose or the audit trail that make its results usable as evidence.

## What it does

On the **Cases** page there is an **Investigate a person** button next to **New case**. It asks for:

- the **one detail** you have (a name, username, email, phone, website or profile link);
- optionally, how to **refer** to the person (defaults to what you typed);
- the **purpose** of the investigation (required, as everywhere in Argus);
- the **legal authorisation**, if your instance requires one;
- how many **rounds** of expansion to run (1–3);
- the confirmation that there is a legitimate purpose and the subject is not a child.

Press go and Argus, in one step:

1. opens a **case** titled *Investigation: &lt;name&gt;* with that purpose (and authorisation);
2. adds the person as a **subject**, with the typed detail as a known detail;
3. **starts a full search** from it, expanding to the requested depth.

You land on the case's **People** tab and watch the candidates arrive, score themselves, and wait for
you to confirm or reject them — exactly as if you had built the case by hand.

## How the detail is read

Argus recognises what you typed and files it under the right known-detail field, so the search knows
how to use it:

| You type | Filed as |
|---|---|
| `jane@example.org` | email |
| `+44 7700 900123` | phone |
| `https://github.com/jane` or `github.com/jane` | profile link |
| `example.com` | website |
| `Jane Doe` (has a space) | name |
| `janedoe84` (one token) | username |

A profile link is handled by the same logic the rest of Argus uses to turn a URL into a handle, so
`x.com/@jane`, `reddit.com/user/jane` and the like are understood.

## What it does *not* change

The one box is a shortcut to the existing machinery, not a new, looser path:

- the **purpose is still required**, and the **authorisation** too where the instance demands it
  (`require_case_authorization`);
- every step is **audited** — the case and subject creation are logged with `via: investigate`;
- the search runs through the **same safety route** and rate limits as a hand-built case;
- the AI dossier, if you ask for one, is a **draft to check**, never a conclusion.

So an investigation that started from a single pasted detail is indistinguishable, afterwards, from one
built click by click: same evidence, same provenance, same accountability.

## Limits

`POST /api/investigate` is rate-limited to **10 a minute** per key, so the one box cannot be used to
spray cases. A blank or too-short purpose, a missing authorisation (where required), or the missing
confirmation each return a clear 422 rather than a half-made case.
