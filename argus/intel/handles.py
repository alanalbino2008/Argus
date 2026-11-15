"""Username variants: the other handles one person is likely to use.

People reuse a handle with small changes: ``jane.roe`` on one site, ``jane_roe`` or ``janeroe`` on
another, ``janeroe1987`` where the plain one was taken. From a full name ("Jane Roe") the usual
forms are ``janeroe``, ``jane.roe``, ``jroe`` and ``roejane``.

Variants are *guesses*: an account found under a variant may well belong to someone else, so
the username hunter marks such finds as possible matches only, with lower confidence.
"""

from __future__ import annotations

import re

MAX_VARIANTS = 6
_SEPARATORS = ("", ".", "_", "-")


def tokens(value: str) -> list[str]:
    """Words in a handle or a name: separators, spaces and camelCase all split."""
    value = re.sub(r"([a-z])([A-Z])", r"\1 \2", value.strip())
    return [t.lower() for t in re.split(r"[\s._\-]+", value) if t]


def variants(value: str, limit: int = MAX_VARIANTS) -> list[str]:
    """Likely alternative handles for ``value`` (a handle or a full name), most likely first."""
    words = tokens(value)
    if not words:
        return []
    core = [re.sub(r"\d+$", "", w) or w for w in words]  # janeroe1987 -> janeroe
    found: list[str] = [sep.join(core) for sep in _SEPARATORS[:3]]  # the plain forms are the likeliest
    found += [sep.join(words) for sep in _SEPARATORS]
    if len(core) > 1:
        first, last = core[0], core[-1]
        found += [first[0] + last, last + first, f"{first[0]}.{last}", first + last[0]]
    original = value.strip().lower()
    clean = [v for v in dict.fromkeys(found) if v != original and re.fullmatch(r"[a-z0-9._-]{3,40}", v)]
    return clean[:limit]
