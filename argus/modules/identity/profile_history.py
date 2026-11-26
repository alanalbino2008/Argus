"""What a profile used to say: the Internet Archive's copies of it.

People rename themselves, rewrite their bios and remove links, but the Wayback Machine often kept
earlier copies of a public profile page. For each profile found (with reasonable confidence), this
module asks the archive for its copies and reads the **oldest** and the **newest**:

* how long the profile has existed (first and last copy) and how many distinct versions there are;
* the name and description it showed then, so an **earlier name** or bio is recorded;
* the links it carried to other social accounts, so an account that was linked once (and may since
  have been deleted or unlinked) is found again.

Only the archive is contacted, never the site or the person.
"""

from __future__ import annotations

import html
import re
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule
from argus.modules.identity.web_mentions import display_name, social_profile

CDX = ("https://web.archive.org/cdx/search/cdx?url={}&output=json&fl=timestamp,statuscode,digest"
       "&filter=statuscode:200&collapse=digest&limit=500")  # fmt: skip
SNAPSHOT = "https://web.archive.org/web/{}id_/{}"
MIN_CONFIDENCE = 0.6
MAX_LINKS = 10
META_RE = re.compile(r"<meta\s+[^>]*(?:property|name)=[\"'](og:title|og:description|description|twitter:title)[\"']"
                     r"[^>]*content=[\"']([^\"']*)[\"']", re.I)  # fmt: skip
META_RE2 = re.compile(r"<meta\s+[^>]*content=[\"']([^\"']*)[\"'][^>]*(?:property|name)=[\"']"
                      r"(og:title|og:description|description|twitter:title)[\"']", re.I)  # fmt: skip
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
HREF_RE = re.compile(r"href=[\"'](https?://[^\"'<>\s]+)[\"']", re.I)


def page_facts(page: str) -> dict[str, Any]:
    """The name, description and social links an archived profile page showed."""
    meta: dict[str, str] = {}
    for key, value in META_RE.findall(page):
        meta.setdefault(key.lower(), html.unescape(value).strip())
    for value, key in META_RE2.findall(page):
        meta.setdefault(key.lower(), html.unescape(value).strip())
    title = meta.get("og:title") or meta.get("twitter:title")
    if not title:
        match = TITLE_RE.search(page)
        title = html.unescape(re.sub(r"\s+", " ", match.group(1))).strip() if match else ""
    links = []
    for href in HREF_RE.findall(page):
        href = re.sub(r"^https?://web\.archive\.org/web/\d+[a-z_]*/", "", html.unescape(href))
        found = social_profile(href)
        if found and found[1] not in links:
            links.append(found[1])
    return {"title": title[:200], "name": display_name(title), "description": (meta.get("og:description")
            or meta.get("description") or "")[:500], "links": links[:MAX_LINKS]}  # fmt: skip


def _date(stamp: str) -> str:
    return f"{stamp[:4]}-{stamp[4:6]}-{stamp[6:8]}" if len(stamp) >= 8 else stamp


class ProfileHistoryModule(BaseModule):
    name = "profile_history"
    description = (
        "Archived copies of a profile: how long it has existed, earlier names and bios, and accounts it once linked to"
    )
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.SOCIAL_PROFILE]
    third_party_safe = True  # the Internet Archive only
    enrichment = True  # also for the profiles found at a search's depth limit
    attack_techniques = ("T1593", "T1594")
    rate_limits: ClassVar[dict[str, float]] = {"web.archive.org": 1.0}

    def can_handle(self, entity: Entity) -> bool:
        return (super().can_handle(entity) and entity.depth <= 1 and entity.confidence >= MIN_CONFIDENCE
                and entity.value.startswith(("https://", "http://")))  # fmt: skip

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        url = entity.value
        async with session.get(CDX.format(quote(url, safe=""))) as resp:
            if resp.status != 200:
                return
            rows = await resp.json()
        stamps = [r[0] for r in (rows or [])[1:] if isinstance(r, list) and r and str(r[0]).isdigit()]
        if not stamps:
            return
        history: dict[str, Any] = {"first_archived": _date(stamps[0]), "last_archived": _date(stamps[-1]),
                                   "versions": len(stamps)}  # fmt: skip
        pages = {}
        for label, stamp in (("oldest", stamps[0]), ("newest", stamps[-1])):
            if label == "newest" and stamp == stamps[0]:
                break
            async with session.get(SNAPSHOT.format(stamp, url)) as resp:
                if resp.status != 200:
                    continue
                text = await resp.text(errors="ignore")
            pages[label] = {**page_facts(text[:500_000]), "date": _date(stamp),
                            "archive_url": f"https://web.archive.org/web/{stamp}/{url}"}  # fmt: skip
        history["snapshots"] = pages
        current = str(((entity.metadata.get("profile") or {}).get("display_name")) or "")
        names = list(dict.fromkeys(p["name"] for p in pages.values() if p.get("name")))
        history["names_shown"] = names
        earlier = [n for n in names if n.lower() != current.lower()] if current else []
        if earlier:
            history["earlier_names"] = earlier
        entity.metadata["history"] = history
        own_host = (urlsplit(url).hostname or "").removeprefix("www.")
        seen: set[str] = set()
        for snap in pages.values():
            for link in snap.get("links") or []:
                host = (urlsplit(link).hostname or "").removeprefix("www.")
                if host == own_host or link in seen:
                    continue
                seen.add(link)
                found = social_profile(link)
                platform = found[0] if found else host
                linked = Entity.create(
                    EntityType.SOCIAL_PROFILE, link, label=f"{platform}: {link.rsplit('/', 1)[-1]}",
                    source_module=self.name, confidence=0.75, depth=entity.depth + 1,
                    metadata={"platform": platform, "origin": f"linked from an archived copy ({snap['date']})",
                              "archive_url": snap["archive_url"], "profile": {"links": [url]}},
                )  # fmt: skip
                yield linked
                yield Relation.create(entity.id, linked.id, RelationType.ASSOCIATED_WITH, confidence=0.75,
                                      label=f"Linked in an archived copy ({snap['date']})")  # fmt: skip
