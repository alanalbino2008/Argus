# 30 — People & Account Investigation (Plain-English Guide)

> Purpose: explain how Argus finds a person's accounts across the web, how it decides which
> accounts belong to the same person, and how it notices when those accounts change. Useful for
> questions like:
> * "how do you avoid false positives when checking hundreds of sites?"
> * "how can you tell two accounts are the same person?"
> * "what is a perceptual hash?"
> * "how do you know an account was deleted, rather than the site just blocking you?"

## 1. Why this matters

Investigations into people usually start from one handle: a username in a scam message, an
account behind a smear campaign, a seller on a marketplace. The same person tends to use the same
or a similar name elsewhere, and each account adds something: a real name, a city, an employer, a
photo, a link to another account. The work is finding those accounts, deciding which really
belong to the same person, and keeping track as they change, often after the subject realises
someone is looking.

## 2. Hundreds of sites, without hundreds of false positives

Argus has always checked about 130 sites, each signature written and tested by hand. It now also
uses **WhatsMyName**, a catalog of hundreds of sites that the OSINT community keeps up to date.
Argus downloads it when needed and caches it for a week; offline installs can use a saved copy.

A bigger list is only useful if it doesn't fill up with wrong answers. Many sites answer "this
profile exists" for any name at all: login walls, rate-limit pages, "page not found" pages that
still return success. Three protections:

1. **Two signatures.** Each community entry says what a real profile shows *and* what a missing
   one shows. Argus checks both.
2. **The made-up name test.** For every site that says "found", Argus also asks about a random
   16-letter name that nobody has registered. If the site claims that one exists too, its answers
   are ignored for the whole search.
3. **Honest confidence.** Hand-checked sites rank above community ones, and unsafe entries
   (sites that need a POST request, plain-HTTP sites, entries the maintainers retired) are skipped
   altogether.

If the catalog can't be downloaded, the built-in sites are still searched.

## 3. Variations of a handle

People adjust their handle when it's taken or when a site's rules differ: `jane.roe` becomes
`jane_roe`, `janeroe` or `janeroe1987`. Ticking **Also try variations** searches the likely forms,
plain versions first (`janeroe`, `jane_roe`, `jroe`, and the handle without its number).

Variations are guesses, so anything found that way is marked **lead**, the weakest grade, and
labelled with the handle it came from. A lead never counts as proof on its own.

## 4. The same photo means (probably) the same person

People change their handle far more often than their profile picture. So Argus compares pictures:

* **On the server, not in your browser.** The pictures are downloaded by Argus (through the case's
  route), so the subject's platforms never see the investigator's address.
* **A perceptual hash.** Argus shrinks each picture to a tiny 9×8 grey grid and records, for each
  pair of neighbouring squares, whether brightness goes up or down: 64 yes/no answers. The same
  photo resized or re-compressed by another site gives almost the same 64 answers (a test finds 1
  difference); a different photo gives dozens.
* **Ignoring pictures that say nothing.** Blank and single-colour images (most sites' default
  avatar) are skipped, and pictures are only compared between *different* sites. Two strangers
  who both kept one forum's stock picture are never linked; a test checks exactly that.

A matching photo groups the accounts into one person and raises a "possible" or "lead" account
to **strong**. It is never **verified**: anyone can copy someone else's photo. Verified still
needs proof from the platform, such as a Keybase signature.

## 5. Watching accounts

A case can **watch** an account. Argus re-reads it every 6 hours, every day or every week:

* **Full profiles** on nine platforms with official public APIs (GitHub, GitLab, Reddit, Hacker
  News, Keybase, Dev.to, Mastodon, Docker Hub, Bluesky): name, bio, location, website, employer,
  public email, linked accounts and the profile picture's fingerprint.
* **Existence** on every other site in the catalog: whether the account is still there.

Each change goes on the case **timeline** as a plain sentence ("Bio: 'Reporter' → 'Freelance
investigator'"), and the account's **history** shows every version. With **capture on change**
(on by default), Argus also preserves the profile page as evidence at that moment, with the same
fingerprints, timestamp and chain of custody as any capture. Follower counts are kept but don't
count as changes, so the timeline isn't flooded.

**Deleted or just blocked?** Sites sometimes refuse automated checks for a while, which can look
like the account vanished. Argus only reports an account gone when:
1. it is missing on **two checks in a row** (the second within the hour), and
2. the site still finds an account **known to exist**, so it is answering properly.

Otherwise the watch shows a "problem" instead of a false "deleted". If the account comes back,
that is recorded too.

**Safety.** Checks go through the case's route. An anonymous case's watch never connects
directly: if its route has been removed, the check is skipped and says why. Every change is in
the audit log, credited to the "account-watcher".

## 6. What a reviewer can check

* `argus/modules/identity/catalog.py`: WhatsMyName conversion and caching.
* `argus/modules/identity/username_hunter.py`: the made-up name test, variants, confidence.
* `argus/intel/handles.py`: handle variations.
* `argus/intel/avatars.py`: the perceptual hash and the "says nothing" filters.
* `argus/intel/identity.py`: grouping by photo; the `possible` grade.
* `argus/intel/account_watch.py`: reading, comparing, the deletion rules, captures on change.
* `argus/storage/watch_repo.py`: atomic claims (one server copy per check) and history.
* `tests/test_people_search.py`:
  * catalog conversion (and what is skipped);
  * a site that says yes to everything is caught;
  * a missing catalog never stops a search;
  * variants are leads;
  * the same photo matches across sizes and formats;
  * strangers with a stock picture aren't linked;
  * the full watch life cycle (baseline, no change, change with capture, missing once, gone,
    back);
  * a blocking site isn't reported as a deletion;
  * anonymous cases never watch directly.
