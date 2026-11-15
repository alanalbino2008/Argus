"""Matching names of people and companies across registers, sanctions lists and leaks.

Names are messy: "SMITH, John Paul", "John P. Smith", "Jóhn Smith"; "Acme Holdings Limited",
"ACME HOLDINGS LTD.", "Acme Holdings, Inc.". A naive comparison misses real matches; a loose one
flags innocent people. Argus:

* normalises: removes accents and punctuation, ignores case, puts "Surname, Given" back in order,
  and for companies drops legal forms (Ltd, LLC, GmbH, S.A., OOO...);
* compares **word by word, in any order**, allowing small spelling differences in each word;
* for people, insists every word of the shorter name matches, so "John Smith" is not "Johnson
  Smithers" and a middle name is optional, not a wildcard;
* returns a **score from 0 to 1** that is shown to the investigator. A match is a lead to check
  (date of birth, nationality, address), never a verdict.
"""

from __future__ import annotations

import re
import unicodedata
from difflib import SequenceMatcher

LEGAL_FORMS = {
    "ltd", "limited", "llc", "l l c", "inc", "incorporated", "corp", "corporation", "co", "company", "plc", "llp",
    "lp", "gmbh", "ag", "sa", "s a", "sas", "sarl", "srl", "spa", "bv", "nv", "oy", "ab", "as", "aps", "kg", "ooo",
    "oao", "zao", "pao", "jsc", "ojsc", "cjsc", "pjsc", "tov", "pte", "pty", "bhd", "sdn", "fze", "fzco", "fzc",
    "dmcc", "the", "group", "holding", "holdings", "public", "joint", "stock", "open", "closed", "private",
    "liability", "partnership", "unitary", "enterprise", "federal", "state", "and",
}  # fmt: skip
_KEEP_GROUP = {"group", "holding", "holdings"}  # dropped only when other words remain


def fold(text: str) -> str:
    """Lower case, no accents, punctuation as spaces."""
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c)).casefold()
    text = re.sub(r"[^\w\s]", " ", text.replace("&", " and "))
    return " ".join(text.split())


def person_tokens(name: str) -> list[str]:
    """Words of a person's name, with "SURNAME, Given" put back in reading order and titles dropped."""
    if "," in name:
        surname, _, given = name.partition(",")
        name = f"{given} {surname}"
    words = fold(name).split()
    return [w for w in words if w not in {"mr", "mrs", "ms", "miss", "dr", "sir", "dame", "lord", "lady", "prof"}]


def company_tokens(name: str) -> list[str]:
    words = fold(name).split()
    core = [w for w in words if w not in LEGAL_FORMS]
    if not core:  # "The Group Ltd": keep what is left rather than nothing
        core = [w for w in words if w in _KEEP_GROUP] or words
    return core


def _word(a: str, b: str) -> float:
    if a == b:
        return 1.0
    if len(a) == 1 or len(b) == 1:  # an initial matches the word it abbreviates
        return 0.9 if a[0] == b[0] else 0.0
    return SequenceMatcher(None, a, b).ratio()


def _best_pairing(short: list[str], long: list[str]) -> list[float]:
    """Greedy best match for each word of the shorter list, each long word used once."""
    used: set[int] = set()
    scores = []
    for word in sorted(short, key=len, reverse=True):
        best, best_i = 0.0, -1
        for i, other in enumerate(long):
            if i not in used:
                s = _word(word, other)
                if s > best:
                    best, best_i = s, i
        if best_i >= 0:
            used.add(best_i)
        scores.append(best)
    return scores


def similarity(a: str, b: str, *, kind: str = "person") -> float:
    """How alike two names are, 0..1, for ``kind`` "person" or "company"."""
    ta = person_tokens(a) if kind == "person" else company_tokens(a)
    tb = person_tokens(b) if kind == "person" else company_tokens(b)
    if not ta or not tb:
        return 0.0
    short, long = (ta, tb) if len(ta) <= len(tb) else (tb, ta)
    scores = _best_pairing(short, long)
    if kind == "person":
        if len(short) == 1 and len(long) > 1:
            return 0.0  # one word ("Smith") never identifies a person
        if min(scores) < 0.8:
            return 0.0  # every word of the shorter name must match
        extra = len(long) - len(short)  # middle names missing on one side: a small penalty each
        return round(sum(scores) / len(scores) * (0.97**extra), 3)
    coverage = sum(scores) / len(long)  # companies: unmatched words count against
    whole = SequenceMatcher(None, " ".join(sorted(ta)), " ".join(sorted(tb))).ratio()
    return round(max(coverage, whole if min(scores) >= 0.8 else 0.0), 3)


def blocking_keys(name: str, *, kind: str) -> set[str]:
    """Cheap keys to find candidates quickly: each word's first three letters."""
    words = person_tokens(name) if kind == "person" else company_tokens(name)
    return {w[:3] for w in words if len(w) >= 3}
