"""Where on the web a phone number or email address has been published.

A number on a scam text, or an email on a fake invoice, has often been used before: in a
classified ad, a forum signature, a company listing, a social media profile, a leaked paste, or a
"who called me?" site where other people reported it. Finding those pages is often how the person
behind it is identified.

The module asks a web search engine (the Brave Search API) for the exact number, written the ways
people write it (``+44 20 7946 0000``, ``020 7946 0000``, ``02079460000``), or the exact email
address. Every result is then **checked**: it is kept only if the number or address really appears
in its title, summary or address. Search engines often return near misses, which are dropped.

Pages are sorted by kind:

* **nuisance and scam reports** ("who called me?" sites where people report numbers);
* **paste sites** (often leaks);
* **social media**;
* **classifieds and marketplaces**;
* other web pages.

The search goes to the search engine, never to the pages themselves or to the person. It needs a
search key: the investigator's own (``ARGUS_WEB_SEARCH_API_KEY``: private, no credits) or Argus
Connect (one credit per search). Invalid numbers are not searched, so no credit is spent on them.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import urlsplit

from argus.accounts.connect_client import available, lookup
from argus.accounts.connectors import ConnectError
from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule
from argus.modules.identity.phone_recon import describe

MAX_KEPT = 15
REPORT_SITES = ("tellows", "whocalled", "who-called", "whocallsme", "800notes", "shouldianswer", "callercenter",
                "unknownphone", "numberguru", "spamcalls", "scamnumbers", "whoisthisnumber", "callercomplaints",
                "reportedcalls", "telguarder", "sync.me", "truecaller")  # fmt: skip
PASTE_SITES = ("pastebin.com", "ghostbin", "paste.ee", "rentry.co", "justpaste.it", "controlc.com", "pastes.io")
SOCIAL_SITES = ("facebook.com", "twitter.com", "x.com", "instagram.com", "linkedin.com", "tiktok.com", "t.me",
                "reddit.com", "youtube.com", "vk.com", "telegram.me", "threads.net", "bsky.app", "pinterest.com")  # fmt: skip
CLASSIFIEDS = ("gumtree", "craigslist", "ebay.", "olx.", "leboncoin", "kijiji", "marketplace", "preloved", "vinted",
               "avito", "locanto", "adverts.ie", "kleinanzeigen", "wallapop", "subito.it")  # fmt: skip


def kind_of(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower().removeprefix("www.")
    if any(site in host for site in REPORT_SITES):
        return "nuisance report"
    if any(host == s or host.endswith("." + s) for s in PASTE_SITES) or "paste" in host:
        return "paste site"
    if any(host == s or host.endswith("." + s) for s in SOCIAL_SITES):
        return "social media"
    if any(site in host for site in CLASSIFIEDS):
        return "classifieds"
    return "web page"


def phone_pattern(national_digits: str) -> re.Pattern[str]:
    """The number's significant digits, with any spacing or punctuation people put between them.

    Whatever comes before them (a country code, a trunk 0, "(0)") is allowed, so "+44 20 7946 0000",
    "020 7946 0000" and "02079460000" all match; more digits after them would be another number.
    """
    return re.compile(r"[\s.\-()/]*".join(map(re.escape, national_digits)) + r"(?!\d)")


class WebMentionsModule(BaseModule):
    name = "web_mentions"
    description = "Where a phone number or email address appears on the web (search engine; own key or credits)"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.PHONE, EntityType.EMAIL]
    third_party_safe = True  # asks a search engine; never contacts the pages or the person
    attack_techniques = ("T1593.002",)

    @classmethod
    def is_configured(cls) -> bool:
        return available("web_search")

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth <= 1

    def _query(self, entity: Entity) -> tuple[str, re.Pattern[str]] | None:
        if entity.type == EntityType.EMAIL:
            address = entity.value.strip().lower()
            if "@" not in address or len(address) > 150:
                return None
            return f'"{address}"', re.compile(re.escape(address), re.I)
        facts = describe(entity.value)
        if not facts or not facts["valid"]:
            return None  # an invented or mistyped number: nothing worth a search
        national = "".join(c for c in facts.get("national", "") if c.isdigit())
        significant = facts["e164"].removeprefix(facts["dial_code"])
        forms = list(dict.fromkeys([facts.get("international", ""), facts.get("national", ""), national,
                                    facts["e164"]]))  # fmt: skip
        query = ""
        for form in (f for f in forms if f):
            candidate = f'{query} OR "{form}"' if query else f'"{form}"'
            if len(candidate) > 150:
                break
            query = candidate
        return query, phone_pattern(significant)

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        built = self._query(entity)
        if built is None:
            return
        query, pattern = built
        try:
            answer = await lookup(session, "web_search", "web", {"q": query})
        except ConnectError as exc:
            self.report_error("web_search", exc.detail)
            return
        results = ((answer.get("web") or {}).get("results") or []) if not answer.get("not_found") else []
        kept: list[dict[str, Any]] = []
        for r in results:
            url = str(r.get("url") or "")
            text = " ".join(str(r.get(k) or "") for k in ("title", "description")) + " " + url
            if not url.startswith(("https://", "http://")) or not pattern.search(text):
                continue  # a near miss: the search engine's guess, not a real mention
            kept.append({"url": url, "title": str(r.get("title") or "")[:200],
                         "snippet": re.sub(r"<[^>]+>", "", str(r.get("description") or ""))[:400],
                         "kind": kind_of(url), "age": r.get("age") or r.get("page_age")})  # fmt: skip
        by_kind: dict[str, int] = {}
        for k in kept:
            by_kind[k["kind"]] = by_kind.get(k["kind"], 0) + 1
        entity.metadata["web_mentions"] = {"searched": query, "results": len(results), "confirmed": len(kept),
                                           "by_kind": by_kind}  # fmt: skip
        order = {"nuisance report": 0, "paste site": 1, "social media": 2, "classifieds": 3, "web page": 4}
        for mention in sorted(kept, key=lambda m: order[m["kind"]])[:MAX_KEPT]:
            page = Entity.create(EntityType.URL, mention["url"], label=mention["title"] or mention["url"],
                                 source_module=self.name, confidence=0.8, depth=entity.depth + 1,
                                 metadata={"category": "mention", "mention_kind": mention["kind"], "out_of_scope": True,
                                           "snippet": mention["snippet"], "page_age": mention["age"],
                                           "origin": "web search"})  # fmt: skip
            yield page
            yield Relation.create(
                entity.id, page.id, RelationType.ASSOCIATED_WITH, label=f"Mentioned on ({mention['kind']})"
            )
