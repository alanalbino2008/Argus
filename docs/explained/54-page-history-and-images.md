# 54 — Page History and Reverse Image Search (Plain-English Guide)

> Purpose: explain two research tools in every case. Useful for questions like:
> * "what did this page say before it was changed or taken down?"
> * "where else has this profile picture been used?"

## 1. Page history

Pages change and disappear: a company's "about us" before a rebrand, a profile before it was
cleaned up, a statement quietly edited. The Internet Archive (the Wayback Machine) keeps
copies.

In a case, **Page history** takes a web address and lists every **different** version the
archive holds, oldest to newest. Identical copies are folded together, so each row is a real
change. For each version you can:

* **Open** it to read it;
* **Capture as evidence**: it goes into the case like any captured page, with a full-page
  screenshot, the text and a fingerprint. It's noted as an archived copy from that date, and
  who captured it is recorded.

Free; no key needed.

## 2. Reverse image search

In a case, **Reverse image search** takes a picture's web address (a profile photo, a product
image, a picture in an article) and shows where else it appears:

* **TinEye inside Argus**: every site and page the picture is on, when TinEye first saw it
  there, and its size. This finds the same photo on other profiles (a sign of a fake or a
  second account) and where a picture was first published. It needs a TinEye key (your own,
  or your administrator's) or an Argus account with credits.
* **One-click searches** on Google Lens, Bing, Yandex and TinEye. These open in your browser,
  and those sites see the picture's address and your connection. The same links appear under
  every profile picture in the entity panel.

No match doesn't prove a picture is original: it may simply not be indexed. Try the other
engines too.

## 3. Privacy

Asking the archive or TinEye tells them which page or picture is being researched. So both
go out through the **case's network route**, like captures, and an anonymous case never asks
directly. Every lookup is recorded in the audit log.

## 4. What a reviewer can check

* `argus/intel/page_history.py`: reading the archive's index, only web addresses accepted.
* `argus/api/research_routes.py`: the endpoints, the case's route, the audit entries, and
  reading TinEye's answer.
* `argus/accounts/connectors.py`: the fixed, validated TinEye lookup.
* `argus/web/js/views/research.js`: the two windows and the search links.
* `tests/test_research_tools.py`:
  * the archive's versions;
  * unsafe addresses refused;
  * TinEye's matches and how its key is sent;
  * no key, no TinEye;
  * audit entries;
  * page history switched off.
