# 44 — Person Profiles, Filled From Scans (Plain-English Guide)

> Purpose: explain how the people a scan finds join a case, and how Argus gathers everything a
> case knows about one person into a single profile. Useful for questions like:
> * "do I have to retype every director a company scan found?"
> * "where can I see everything we know about this person?"
> * "how does Argus avoid adding the wrong people?"

## 1. Why this matters

A scan of a company finds its directors and owners; a scan of a username finds the accounts and
the name behind them. Retyping all that into the case is slow, and things get missed. And once a
case has dozens of people, notes and documents, finding everything about one of them means
reading it all again.

## 2. People join the case from scans

**Automatically.** When a scan linked to a case finishes, whether started from the case or by a
playbook, Argus adds the people and organisations the scan is fairly sure of (80% or more). It
also adds the relationships between them:

| What the scan found | Becomes |
|---|---|
| an officer of a company | **director of** that company |
| a person with significant control | **owner of** that company |
| the owner of an account | **uses** that account |
| two wallets spent together | **shares a wallet with** |

* **Dates kept.** Appointment and resignation dates become the relationship's start and end.
* **Source noted.** Each new entry says which scan it came from and what the scan learned: role,
  date of birth, nationality, and a possible sanctions match if there was one.
* **Never added twice.** An entry already in the case (the same kind and name, however it's
  capitalised or spaced) isn't added again.
* **Left out:** things found only *about* third parties (for example impostor websites), and very
  weak finds.

**By hand.** Everything else a scan found can be added from **From scans** in the case's People &
entities card: accounts, usernames, emails, phone numbers, wallets, places, and people the scan
was less sure of. You tick what you want, and the relationships between them come too.

## 3. A profile for each person

Click a person or organisation in the case, or use **Open full profile** on the link chart.

| Section | What it shows |
|---|---|
| **Details** | everything recorded about them, and notes |
| **Relationships** | every link to other people and organisations: the kind, how sure, since when, until when, and why |
| **Accounts and contacts** | usernames, accounts, emails, phones, wallets and websites linked to them |
| **Places** | addresses and locations linked to them or recorded about them |
| **Place in the network** | how connected they are, their group, and whether they're a key person or a go-between |
| **What scans found** | from linked scans: date of birth, nationality, directorships with dates, possible sanctions matches (and details that suggest a different person), Offshore Leaks, public profile details |
| **Timeline** | dated events naming them, when relationships began and ended, appointments and resignations from company registers |
| **Mentioned in** | every note, event and evidence document that names them, or their usernames and contacts, with the passage around each mention |

The profile is built only from what's already in the case and its linked scans. Opening it
doesn't search anything new.

## 4. Safeguards

* **Protected people** (for example, children) have no profile. Their name is blanked out of the
  passages shown in other people's profiles.
* **Viewing a profile** is recorded in the audit log, like opening a case.
* **Name matches stay possibilities.** A sanctions match shows any details that contradict it,
  and people a scan found by name alone stay marked as less certain.

## 5. What a reviewer can check

* `argus/intel/people_import.py`:
  * what a scan's graph offers the case (`proposals`);
  * what is added automatically (`automatic`);
  * how scan relations become relationship kinds.
* `argus/intel/dossier.py` (`build_profile`): how a profile is assembled.
* `argus/api/people_routes.py`:
  * the endpoints;
  * the automatic import after a scan (`auto_import`), called from `argus/api/server.py` and the
    playbook runner.
* `argus/web/js/views/profile.js`, `cases.js` and `casechart.js`: the profile window, the "From
  scans" dialog and the link chart button.
* `tests/test_people_case.py`:
  * what a company scan offers;
  * what's left out;
  * the automatic import, with dates, wording and no duplicates;
  * adding an account by hand;
  * a full profile, with a protected child blanked out;
  * the protected person's own (empty) profile.
