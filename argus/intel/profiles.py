"""Are two accounts the same person? Compare what their public profiles say.

The same username on two sites is only a lead: common handles are taken by many people. The
profiles themselves usually settle it. This module compares two profiles' public facts and lists
what **agrees** and what **conflicts**, so the investigator sees the reasons, not just a score:

* **links**: one profile links to the other, or both link to the same website (strongest);
* **photo**: the same profile picture (compared by image fingerprint, so resized or re-compressed
  copies still match);
* **name**: the same display name (compared word by word, so "Jane A. Roe" and "Roe, Jane" agree);
  two different real names is a conflict;
* **bio**: bios that share several distinctive words;
* **location**: the same place; two different places is a (weak) conflict.

The verdict:

* ``same``: a link between them, or at least two independent agreements and no conflict;
* ``likely``: one agreement and no conflict;
* ``different``: conflicts and nothing in common;
* ``unclear``: anything else, including too little to compare.
"""

from __future__ import annotations

import re
import unicodedata
from typing import Any
from urllib.parse import urlsplit

from argus.intel.avatars import same_picture
from argus.intel.names import similarity

STOPWORDS = {"a", "an", "and", "are", "as", "at", "be", "but", "by", "for", "from", "has", "have", "i", "im", "i'm", "in", "into", "is", "it", "its", "just", "me", "my", "of", "on", "or", "our", "so", "that", "the", "their", "this", "to", "was", "we", "were", "with", "you", "your", "about", "all", "also", "am", "can", "do", "get", "here", "like", "more", "new", "not", "now", "one", "out", "see", "than", "then", "they", "up", "what", "when", "who", "will", "love", "life", "living", "based", "official", "account", "page", "profile", "welcome", "hello", "hi", "follow", "followers", "following", "posts", "post", "photos", "videos", "news"}  # fmt: skip
GENERIC_HOSTS = {"linktr.ee", "linktree.com", "bio.link", "beacons.ai", "carrd.co", "google.com", "youtube.com",
                 "facebook.com", "instagram.com", "twitter.com", "x.com", "t.co", "bit.ly", "goo.gl"}  # fmt: skip


def _words(text: str) -> set[str]:
    text = unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()
    return {w for w in re.findall(r"[a-z][a-z0-9']{3,}", text) if w not in STOPWORDS}


def _host(url: str) -> str:
    return (urlsplit(url if "//" in url else f"https://{url}").hostname or "").lower().removeprefix("www.")


def _norm_url(url: str) -> str:
    parts = urlsplit(url if "//" in url else f"https://{url}")
    return f"{(parts.hostname or '').lower().removeprefix('www.')}{parts.path.rstrip('/').lower()}"


def _urls(links: Any) -> list[str]:
    """Link URLs, whether stored as plain strings or as {"url": ...} records."""
    out = []
    for item in links or []:
        url = item.get("url") if isinstance(item, dict) else item
        if url:
            out.append(str(url))
    return out


def _place(text: str) -> set[str]:
    return {w for w in re.findall(r"[a-z]{3,}", unicodedata.normalize("NFKD", text).lower()) if w not in STOPWORDS}


def _real_name(name: str) -> bool:
    return len(name.split()) >= 2 and not any(c.isdigit() for c in name)


def compare(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Compare two profiles: ``a`` and ``b`` hold ``facts`` (display_name, bio, location, website,
    links, avatar_hash) and ``url`` (the profile's own address)."""
    fa, fb = a.get("facts") or {}, b.get("facts") or {}
    agree: list[str] = []
    conflict: list[str] = []
    linked = False

    links_a = {_norm_url(u) for u in _urls(fa.get("links"))}
    links_b = {_norm_url(u) for u in _urls(fb.get("links"))}
    if a.get("url") and _norm_url(a["url"]) in links_b:
        agree.append("the other profile links to this one")
        linked = True
    if b.get("url") and _norm_url(b["url"]) in links_a:
        agree.append("this profile links to the other one")
        linked = True
    sites_a = {_host(u) for u in [fa.get("website") or "", *links_a] if u} - GENERIC_HOSTS - {""}
    sites_b = {_host(u) for u in [fb.get("website") or "", *links_b] if u} - GENERIC_HOSTS - {""}
    shared_sites = sites_a & sites_b
    if shared_sites:
        agree.append(f"both link to {', '.join(sorted(shared_sites)[:2])}")
        linked = True

    if same_picture(a.get("avatar_hash") or fa.get("avatar_hash"), b.get("avatar_hash") or fb.get("avatar_hash")):
        agree.append("the same profile photo")

    name_a, name_b = str(fa.get("display_name") or "").strip(), str(fb.get("display_name") or "").strip()
    if name_a and name_b:
        score = similarity(name_a, name_b, kind="person") if _real_name(name_a) and _real_name(name_b) else (
            1.0 if name_a.lower() == name_b.lower() else 0.0)  # fmt: skip
        if score >= 0.9:
            agree.append(f"the same name ({name_a})")
        elif _real_name(name_a) and _real_name(name_b) and score < 0.5:
            conflict.append(f"different names ({name_a} / {name_b})")

    words_a, words_b = _words(str(fa.get("bio") or "")), _words(str(fb.get("bio") or ""))
    shared_words = words_a & words_b
    if len(shared_words) >= 3 or (shared_words and len(shared_words) / max(1, min(len(words_a), len(words_b))) >= 0.5
                                  and len(shared_words) >= 2):  # fmt: skip
        agree.append(f"similar bios ({', '.join(sorted(shared_words)[:4])})")

    place_a, place_b = _place(str(fa.get("location") or "")), _place(str(fb.get("location") or ""))
    if place_a and place_b:
        if place_a & place_b:
            agree.append(f"the same place ({fa.get('location')})")
        else:
            conflict.append(f"different places ({fa.get('location')} / {fb.get('location')})")

    independent = len({reason.split(" (")[0] for reason in agree})
    if linked or (independent >= 2 and not conflict):
        verdict = "same"
    elif independent == 1 and not conflict:
        verdict = "likely"
    elif conflict and not agree:
        verdict = "different"
    else:
        verdict = "unclear"
    return {"verdict": verdict, "agree": agree, "conflict": conflict}
