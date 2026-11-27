"""Ransomware-ecosystem intelligence: the leak-site landscape, read from a public research feed.

Argus never visits ransomware leak sites (Tor hidden services run by criminals). This hub reads the
same lawful research feed the exposure monitor uses (ransomware.live's API, which indexes the posts
groups publish about their victims) and turns the recent posts into an at-a-glance picture:

* **recent victims** — the latest leak-site posts, filterable by group, sector and country;
* **group tracking** — which groups are active and how much, from the recent window;
* **new-group detection** — groups appearing for the first time since Argus last looked (a stored
  snapshot of the group names seen before), which often marks a rebrand or a new operation;
* **ecosystem stats** — posts in the last 7 and 30 days, and the busiest groups, sectors and countries.

Only metadata is handled — victim name, group, date, sector, country — never leaked files.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta
from typing import Any

from argus.intel.exposure import _victim_fields, parse_time

KNOWN_GROUPS_KEY = "ransomware_known_groups"
MAX_POSTS = 400


def normalise(post: dict[str, Any]) -> dict[str, Any]:
    """One leak-site post in a stable shape (the feed's fields vary between versions)."""
    f = _victim_fields(post)
    published = parse_time(f["published"])
    return {
        "victim": f["victim"][:200] or "(unnamed)",
        "group": (f["group"] or "unknown")[:80],
        "website": str(f["website"] or "")[:200],
        "published": published.date().isoformat() if published else None,
        "country": (str(f["country"]).upper()[:3] if f["country"] else None),
        "sector": (str(f["sector"])[:80] if f["sector"] else None),
        "id": str(f["id"] or "")[:200] or None,
    }


def recent_posts(posts: list[dict[str, Any]], *, limit: int = MAX_POSTS) -> list[dict[str, Any]]:
    """Normalise and sort posts newest-first, de-duplicated."""
    seen: set[tuple[str, str, str | None]] = set()
    out: list[dict[str, Any]] = []
    for post in posts:
        if not isinstance(post, dict):
            continue
        n = normalise(post)
        key = (n["group"].lower(), n["victim"].lower(), n["published"])
        if key in seen:
            continue
        seen.add(key)
        out.append(n)
    out.sort(key=lambda p: p["published"] or "", reverse=True)
    return out[:limit]


def filter_posts(
    posts: list[dict[str, Any]], *, group: str = "", country: str = "", sector: str = "", q: str = ""
) -> list[dict[str, Any]]:
    g, c, s, query = group.lower().strip(), country.upper().strip(), sector.lower().strip(), q.lower().strip()
    out = posts
    if g:
        out = [p for p in out if p["group"].lower() == g]
    if c:
        out = [p for p in out if (p["country"] or "") == c]
    if s:
        out = [p for p in out if s in (p["sector"] or "").lower()]
    if query:
        out = [p for p in out if query in p["victim"].lower() or query in (p["website"] or "").lower()]
    return out


def _top(values: list[str], limit: int = 12) -> list[dict[str, Any]]:
    return [{"name": name, "count": count} for name, count in Counter(v for v in values if v).most_common(limit)]


def facets(posts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Group / sector / country breakdowns of a set of posts, busiest first."""
    return {
        "groups": _top([p["group"] for p in posts], 20),
        "sectors": _top([p["sector"] or "" for p in posts]),
        "countries": _top([p["country"] or "" for p in posts]),
    }


def stats(posts: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    """Headline counts: posts in the last 7 and 30 days, and the daily count for the last fortnight."""
    today = now.date()
    last7 = sum(1 for p in posts if _within(p["published"], today, 7))
    last30 = sum(1 for p in posts if _within(p["published"], today, 30))
    by_day = []
    for i in range(13, -1, -1):
        day = (today - timedelta(days=i)).isoformat()
        by_day.append({"day": day, "count": sum(1 for p in posts if p["published"] == day)})
    return {
        "total": len(posts),
        "last_7_days": last7,
        "last_30_days": last30,
        "active_groups": len({p["group"] for p in posts}),
        "by_day": by_day,
    }


def _within(published: str | None, today: Any, days: int) -> bool:
    if not published:
        return False
    try:
        d = datetime.fromisoformat(published).date()
    except ValueError:
        return False
    return 0 <= (today - d).days < days


def detect_new_groups(posts: list[dict[str, Any]], known: set[str]) -> tuple[list[str], set[str]]:
    """Groups in the recent window not seen before, and the updated known-group set to persist.

    A brand-new group name is a strong signal (a new operation, or a rebrand of an old one)."""
    current = {p["group"] for p in posts if p["group"] and p["group"] != "unknown"}
    new = sorted(g for g in current if g.lower() not in {k.lower() for k in known})
    return new, known | current
