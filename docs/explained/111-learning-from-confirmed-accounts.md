# 111. Learning from confirmed accounts

Confirming an account (**Theirs**) used to add only the account itself to what is known. A
confirmed profile usually says much more about the person. Argus now offers that for you to add,
and searches from what you keep.

## What is suggested

When you confirm a candidate, Argus lists what it shows that is not known yet:

| Suggestion | Taken from |
| --- | --- |
| Name | the name the account shows (a married name, a fuller name), when it differs from the known ones |
| Town or city | the account's location, when no town is known |
| Employer | the account's company (LinkedIn, ORCID…), or the company a register record links them to, when none is known |
| Website | the website and links on the profile, and web addresses in the bio |
| Account | links to their accounts on other networks, on the profile or written in the bio (`tiktok.com/@...`) |
| Email address | addresses the account shows publicly (in the bio, or a business account's contact) |
| Phone number | a number the account shows publicly |

Already known details, the account itself and link pages (Linktree and similar) are not suggested.

## Nothing is added on its own

A bio can mention a friend's account, a shop the person works for, or an old job. So suggestions
wait in **Found on confirmed accounts**, on the person's card, each with where it came from. Tick
what is theirs:

* **Add ticked and search** adds them to the known details, scores every candidate again against
  them, and searches from them straight away;
* **Dismiss ticked** removes them; they are not suggested again.

Accepting is audited (`subject.learn`).

## Searches pick up what you learn

* Confirming an account now always searches whatever became known that has not been searched yet:
  the account itself (its archived copies, public page, and profile viewer) and its handle.
* Details that become known **while a search is running** (a confirmation, an accepted suggestion,
  an edit) are searched by that running search before it finishes.

Each round of confirming and accepting adds to what is known, which finds more, which you review in
turn. Every step is yours to approve, so a mistake does not spread on its own.

## API

* `POST /api/cases/{case}/subjects/{id}/suggestions/accept` with `{"ids": [...], "search": true}`;
* `POST /api/cases/{case}/subjects/{id}/suggestions/dismiss` with `{"ids": [...]}`;
* the pending suggestions are in the person's `suggestions`.
