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


SOCIAL_QUERY = ("site:facebook.com", "site:instagram.com", "site:linkedin.com/in", "site:x.com", "site:tiktok.com",
                "site:snapchat.com", "site:t.me", "site:threads.net", "site:youtube.com", "site:pinterest.com", "site:twitter.com")  # fmt: skip
PLATFORM_NAMES = {"facebook.com": "Facebook", "instagram.com": "Instagram", "linkedin.com": "LinkedIn",
                  "x.com": "X", "twitter.com": "X", "tiktok.com": "TikTok", "threads.net": "Threads",
                  "youtube.com": "YouTube", "pinterest.com": "Pinterest", "snapchat.com": "Snapchat",
                  "t.me": "Telegram"}  # fmt: skip
NOT_PROFILES = ("/posts/", "/status/", "/p/", "/reel/", "/video/", "/watch", "/groups/", "/events/", "/pin/",
                "/pulse/", "/jobs/", "/company/", "/school/", "/hashtag/", "/explore/", "/search", "/share")  # fmt: skip


MAX_QUERY = 160  # what the search connector accepts


def social_query(subject: str) -> str:
    """The subject on the big social networks, most used first, as many as fit in one query."""
    query = subject
    for n in range(len(SOCIAL_QUERY), 0, -1):
        query = f"{subject} ({' OR '.join(SOCIAL_QUERY[:n])})"
        if len(query) <= MAX_QUERY:
            return query
    return subject


TELEGRAM_RESERVED = {"joinchat", "addstickers", "addemoji", "share", "proxy", "socks", "addlist", "addtheme",
                     "setlanguage", "boost", "contact", "iv", "login", "confirmphone"}  # fmt: skip


def name_pattern(name: str) -> re.Pattern[str]:
    """The name's words in order, with anything short between them (a middle name or initial)."""
    words = [re.escape(w) for w in name.split()]
    return re.compile(r"\b" + r"(?:\s+\S{1,15})?\s+".join(words) + r"\b", re.I)


def social_profile(url: str) -> tuple[str, str] | None:
    """(platform, profile address) when a search result is a profile page on a big social network."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().removeprefix("www.").removeprefix("m.")
    host = host.split(".", 1)[1] if host.count(".") > 1 and host.endswith("linkedin.com") else host
    platform = PLATFORM_NAMES.get(host)
    path = parts.path.rstrip("/")
    if platform is None or not path or any(bad in path.lower() + "/" for bad in NOT_PROFILES):
        return None
    segments = [s for s in path.split("/") if s]
    if platform == "LinkedIn":
        if len(segments) < 2 or segments[0] != "in":
            return None
        segments = segments[:2]
    elif platform == "Snapchat":
        if len(segments) < 2 or segments[0] != "add":
            return None
        segments = segments[:2]
    elif platform == "Telegram":
        if segments[0] == "s" and len(segments) > 1:
            segments = segments[1:]
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{4,31}", segments[0]) or segments[0].lower() in TELEGRAM_RESERVED:
            return None  # invite links (+..., joinchat), stickers, sharing and other non-profile pages
        segments = segments[:1]
    elif platform == "Facebook" and segments[0] == "people" and len(segments) >= 3:
        segments = segments[:3]
    else:
        segments = segments[:1]
    if platform == "Facebook" and segments[0] in ("profile.php", "pages", "public", "login", "watch", "marketplace"):
        return None
    host = "x.com" if platform == "X" else host  # twitter.com and x.com are one account
    www = "www." if platform in ("LinkedIn", "Facebook", "Instagram", "Pinterest") else ""
    return platform, f"https://{www}{host}/{'/'.join(segments)}"


def display_name(title: str) -> str:
    """The person's name from a profile page's title ("Jane Doe (@jdoe) • Instagram photos and videos")."""
    head = re.split(r"\s+[-|•·(]\s*|\s+on\s+|\s+\(", title or "", maxsplit=1)[0].strip()
    return head if 2 <= len(head) <= 80 and len(head.split()) <= 6 else ""


def phone_pattern(national_digits: str) -> re.Pattern[str]:
    """The number's significant digits, with any spacing or punctuation people put between them.

    Whatever comes before them (a country code, a trunk 0, "(0)") is allowed, so "+44 20 7946 0000",
    "020 7946 0000" and "02079460000" all match; more digits after them would be another number.
    """
    return re.compile(r"[\s.\-()/]*".join(map(re.escape, national_digits)) + r"(?!\d)")


class WebMentionsModule(BaseModule):
    name = "web_mentions"
    description = (
        "Where a phone number, email address, username or person appears on the web, including public "
        "profiles on the big social networks (search engine; own key or credits)"
    )
    supported_entity_types: ClassVar[list[EntityType]] = [
        EntityType.PHONE,
        EntityType.EMAIL,
        EntityType.USERNAME,
        EntityType.PERSON,
    ]
    third_party_safe = True  # asks a search engine; never contacts the pages or the person
    attack_techniques = ("T1593.002",)

    @classmethod
    def is_configured(cls) -> bool:
        return available("web_search")

    def can_handle(self, entity: Entity) -> bool:
        if entity.type in (EntityType.PERSON, EntityType.USERNAME):  # a credit per search: the starting point only
            return super().can_handle(entity) and entity.depth == 0
        return super().can_handle(entity) and entity.depth <= 1

    def _queries(self, entity: Entity, hints: dict[str, Any]) -> list[tuple[str, re.Pattern[str]]]:
        if entity.type == EntityType.PERSON:
            name = " ".join(entity.value.split())
            if len(name.split()) < 2 or len(name) > 80:
                return []
            pattern = name_pattern(name)
            context = [str(hints[k])[:60] for k in ("city", "employer") if hints.get(k)]
            queries = [social_query(f'"{name}"')]
            if context:
                queries.append(f'"{name}" ' + " ".join(f'"{c}"' for c in context))
            queries.append(f'"{name}" (filetype:pdf OR filetype:doc OR filetype:docx)')
            return [(q, pattern) for q in queries]
        if entity.type == EntityType.USERNAME:
            handle = entity.value.strip().lstrip("@")
            if not re.fullmatch(r"[A-Za-z0-9._-]{3,40}", handle):
                return []
            pattern = re.compile(r"(?<![A-Za-z0-9])@?" + re.escape(handle) + r"(?![A-Za-z0-9])", re.I)
            return [(f'"{handle}"', pattern), (social_query(f'"{handle}"'), pattern)]
        built = self._query(entity)
        return [built] if built else []

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
        queries = self._queries(entity, config.hints or {})
        if not queries:
            return
        kept: list[dict[str, Any]] = []
        seen: set[str] = set()
        total = 0
        for query, pattern in queries:
            try:
                answer = await lookup(session, "web_search", "web", {"q": query})
            except ConnectError as exc:
                self.report_error("web_search", exc.detail)
                break
            results = ((answer.get("web") or {}).get("results") or []) if not answer.get("not_found") else []
            total += len(results)
            for r in results:
                url = str(r.get("url") or "")
                text = " ".join(str(r.get(k) or "") for k in ("title", "description")) + " " + url
                if not url.startswith(("https://", "http://")) or not pattern.search(text) or url in seen:
                    continue  # a near miss: the search engine's guess, not a real mention
                seen.add(url)
                kept.append({"url": url, "title": str(r.get("title") or "")[:200],
                             "snippet": re.sub(r"<[^>]+>", "", str(r.get("description") or ""))[:400],
                             "kind": kind_of(url), "age": r.get("age") or r.get("page_age")})  # fmt: skip
        by_kind: dict[str, int] = {}
        for k in kept:
            by_kind[k["kind"]] = by_kind.get(k["kind"], 0) + 1
        entity.metadata["web_mentions"] = {"searched": " | ".join(q for q, _ in queries), "results": total,
                                           "confirmed": len(kept), "by_kind": by_kind}  # fmt: skip
        order = {"nuisance report": 0, "paste site": 1, "social media": 2, "classifieds": 3, "web page": 4}
        for mention in sorted(kept, key=lambda m: order[m["kind"]])[:MAX_KEPT]:
            profile = (
                social_profile(mention["url"]) if entity.type in (EntityType.PERSON, EntityType.USERNAME) else None
            )
            if profile is not None:
                platform, url = profile
                account = Entity.create(
                    EntityType.SOCIAL_PROFILE, url, label=f"{platform}: {mention['title'] or url}"[:200],
                    source_module=self.name, confidence=0.5, depth=entity.depth + 1,
                    metadata={"platform": platform, "origin": "found by web search", "snippet": mention["snippet"],
                              "profile": {"display_name": display_name(mention["title"]),
                                          "bio": mention["snippet"]}},
                )  # fmt: skip
                yield account
                yield Relation.create(entity.id, account.id, RelationType.HAS_ACCOUNT, confidence=0.5,
                                      label=f"Possible {platform} profile (web search)")  # fmt: skip
                continue
            page = Entity.create(EntityType.URL, mention["url"], label=mention["title"] or mention["url"],
                                 source_module=self.name, confidence=0.8, depth=entity.depth + 1,
                                 metadata={"category": "mention", "mention_kind": mention["kind"], "out_of_scope": True,
                                           "snippet": mention["snippet"], "page_age": mention["age"],
                                           "origin": "web search"})  # fmt: skip
            yield page
            yield Relation.create(
                entity.id, page.id, RelationType.ASSOCIATED_WITH, label=f"Mentioned on ({mention['kind']})"
            )
