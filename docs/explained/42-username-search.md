# 42 — Bigger Username Search, and Same-Person Checks (Plain-English Guide)

> Purpose: explain how Argus searches for a username across thousands of sites without drowning
> the investigator in false matches, and how it judges whether accounts belong to the same person.
> Useful for questions like:
> * "how many sites does Argus check?"
> * "the same username is on 40 sites: are they all the same person?"
> * "why does Argus say this account is doubtful?"

## 1. Why this matters

People reuse usernames. Finding every site where a username exists is a quick way to map
someone's online life. But two problems come with it:

* **False positives.** Many sites answer "yes, that profile exists" for any name, or show a
  sign-in page that looks like a profile.
* **Other people.** Common usernames are taken by many people. "janeroe" on a forum may be
  someone else entirely.

Argus deals with both. The first by checking every site against a made-up name; the second by
comparing what the profiles themselves say.

## 2. More sites

Argus now checks three lists:

| List | Sites | Notes |
|---|---|---|
| Argus's own | about 130 | checked by hand |
| WhatsMyName | about 600 | community-maintained |
| **Maigret** (new) | about 8,000 usable; the most visited 3,000 checked by default | community-maintained, MIT licence |

* **Each site once.** A site in more than one list is checked once, using the best source.
* **Unsafe entries skipped.** Entries Argus can't check safely are left out: plain-HTTP sites,
  sites that only reveal a profile through a redirect, and entries the maintainers marked broken.
* **Ranked by popularity.** The Maigret list includes thousands of tiny forums. The most visited
  sites come first, and the limit (`ARGUS_USERNAME_CATALOG_EXTRA_LIMIT`) keeps a search to a few
  minutes.
* **Calibrated.** Every site that says "yes" is checked against a random name nobody uses. If it
  says "yes" to that too, it's ignored for this search.

## 3. What profiles say

Knowing an account exists is only the start. Argus reads what each profile publicly says about
its owner:

* from **official interfaces** where a site has one (GitHub, GitLab, Reddit, Mastodon, Bluesky
  and others);
* from **the public page itself** for every other site. Most sites put the profile's name, bio
  and photo into the page for link previews, often with links to the owner's other accounts.

Argus ignores what isn't about the person: a title that's just the username or the site's name, a
description that's the site's own sales pitch, a sign-in page. Only public pages are read, never
anything behind a login.

## 4. Same person or not

Each account's profile is compared with the person's other accounts:

| Agrees | Conflicts |
|---|---|
| one profile **links to the other** | **different real names** |
| both link to **the same website** | **different places** |
| **the same photo** (matched even when resized) | |
| **the same name** ("Jane A. Roe" and "Roe, Jane" agree) | |
| **similar bios** (several distinctive words in common) | |
| **the same place** | |

The verdict:

* **Same person**: a link between them, or two separate agreements and no conflict. An account
  that was only a guess ("the username exists there") becomes **Strong**.
* **Probably the same**: one agreement and no conflict.
* **Doubtful**: conflicts and nothing in common. For example, the forum account is "Johan
  Eriksson in Stockholm", while her other accounts are "Jane Roe in Leeds".
* **Unclear**: not enough to compare.

On the People page each account shows its reasons, in plain words:

* "Same person as the GitHub account: both link to janeroe.example";
* "Probably a different person from the GitHub account: different names (Johan Eriksson /
  Jane Roe)".

The investigator decides; Argus shows the evidence.

## 5. What a reviewer can check

* `argus/modules/identity/maigret_catalog.py`: reading the Maigret list, popularity order, the
  limit.
* `argus/modules/identity/username_hunter.py` (`all_platforms`): each site once, across all lists.
* `argus/modules/identity/page_profile.py`: reading public profile pages, and what's ignored.
* `argus/intel/profiles.py` (`compare`): the agreements, conflicts and verdicts.
* `argus/intel/identity.py` (`corroborate`): grading accounts in the People view.
* `tests/test_profiles.py`:
  * the Maigret list read safely;
  * popularity order;
  * the limit and caching;
  * each site checked once;
  * profile pages read, and sign-in pages ignored;
  * eight comparison cases;
  * the People view upgrading one account and marking another doubtful.
