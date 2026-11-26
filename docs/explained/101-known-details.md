# 101. Known details: start from what you already know about a person

An investigation into a person rarely starts from nothing. The investigator usually knows a name,
perhaps a username or two, an email address from a message, a phone number, a link to one of their
accounts, the town they live in and where they work. Until now each of those had to be searched on
its own, with a playbook, and the results compared by eye.

A **person** in a case (a *subject*) now holds everything known about them, and one search runs from
all of it.

## What you can enter

| Known detail | How it is used |
| --- | --- |
| Full names (and other names they use) | Searched in company registers, sanctions lists and offshore leaks; compared with the names on accounts found |
| Usernames | Searched on hundreds of sites, with likely variants |
| Email addresses | Searched like the *Email footprint* playbook; an account showing one counts in its favour |
| Phone numbers | Searched like the *Phone number* playbook; an account showing one counts in its favour |
| Links to their accounts | Searched by the handle in the link; an account linking to one counts in its favour |
| Websites | Registration and the site itself are searched; an account linking to it counts in its favour |
| Town or city, employer | Compared with what accounts and records say |
| Year of birth | **Only used to rule matches out** (a record of someone born in 1951 is not a 1984-born person) |
| A photo | Only a fingerprint is kept (the image itself is not stored), to recognise the same picture on a profile |

## One search from everything

**Search from what is known** searches every known detail that has not been searched before (or all
of them again, if asked). Each search uses the same sources as the matching playbook, the case's
route, and only passive sources in an anonymous case. Every scan is linked to the case, counted
against the workspace's quotas, and audited.

Everything found (accounts, usernames, email addresses, phone numbers, register records) becomes a
**candidate**, merged with the same thing found by another search. Things already known are not
candidates.

How far it goes is chosen each time: known details only, one step further, or two. A step further
means: a candidate that matches **very well (80 or more)** is searched in turn (an account by its
handle), up to 40 searches a run. Everything else waits for the investigator.

## How candidates are scored

Each candidate is compared with what is known:

* **For it**: the same name, the same profile photo, the same town, the employer named, a link to a
  known account or website, a known email address or phone number shown on it, born about the same
  year.
* **Against it**: a different name, a different town, a different year of birth.

The score starts from how the candidate was found (verified, for example by the email provider: 60;
strong: 45; probable, such as a handle existing on a site: 25; a variant of the handle: 10), adds 20
for each agreement (up to three) and takes 30 off for each contradiction.

| Verdict | Meaning |
| --- | --- |
| Likely theirs | 70 or more |
| Possible | 40 to 69 |
| Weak | under 40 |
| Probably not | a contradiction and nothing for it, or a contradiction and under 40 |

The reasons are always shown. Scores are aids to judgement, never identifications: two people can
share a name, a town and even a photo.

## Confirm or reject

* **Theirs**: the candidate becomes a known detail, is added to the case as an entity (with the
  reasons), every other candidate is scored again against it, and, if its handle has not been
  searched, it is searched straight away.
* **Not theirs**: it is never suggested for this person again, even when everything is searched
  again. **Undo** puts it back.

Confirming and rejecting are audited (`subject.confirm`, `subject.reject`).

## Safeguards

* A person can only be added, and a search started, with a confirmed legitimate purpose; the case's
  purpose is recorded with each.
* Argus refuses a person whose year of birth makes them under 18.
* A closed case cannot be searched from; one search per person at a time, which can be stopped.
* Names and everything known and found are encrypted at rest with the case vault.
* A run left unfinished by a restart is marked *interrupted*.

## The API

| Method | Path | |
| --- | --- | --- |
| `GET`, `POST` | `/api/cases/{case}/subjects` | list, add (`name`, `known`, `confirmed`) |
| `GET`, `PUT`, `DELETE` | `/api/cases/{case}/subjects/{id}` | read with candidates, change, remove |
| `POST`, `DELETE` | `.../{id}/photo` | add a known photo (fingerprint only), remove it |
| `POST` | `.../{id}/run` | search (`confirmed`, `rounds` 1–3, `fresh`) |
| `POST` | `.../{id}/run/cancel` | stop |
| `POST` | `.../{id}/candidates/{cid}/confirm`, `/reject`, `/reopen` | review |
| `PUT` | `.../{id}/watch` | weekly watch on or off (see 102) |
