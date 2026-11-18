"""Reads a whole website, page by page, and lists what it publishes about whoever runs it.

The home page rarely says much. Who runs a fake charity or a scam shop is usually given away
deeper in: a contact email on the terms page, a phone number in the footer of the delivery page, a
donation wallet, a link to the owner's real social media account, a PDF annual report, an
analytics ID shared with their other sites.

For a website, this module:

* starts from the home page and the site's own sitemap, then follows links **within the site**
  (never to other websites), up to a set number of pages (``ARGUS_CRAWL_MAX_PAGES``, default 40);
* **obeys robots.txt**: pages the owner asked crawlers to avoid are not visited, and counted;
* waits between pages (``ARGUS_CRAWL_DELAY_SECONDS``) so it never strains the site;
* reads only web pages, at most 600 KB each;
* lists email addresses, phone numbers (with a country code), crypto wallets (checksums
  verified), social media accounts it links to, documents it offers (PDF, Word, Excel...),
  analytics and advertising IDs, and the other websites it links to.

It contacts the website itself, so it is *active*: passive-only and anonymous cases skip it.
Up to ten documents on the site itself are opened to read their hidden metadata: who wrote them,
for which company, and with what software.
Other websites linked to are recorded by name only, never visited or scanned.
"""

from __future__ import annotations

import asyncio
import re
from collections import deque
from collections.abc import AsyncIterator
from html import unescape
from typing import Any, ClassVar
from urllib.parse import urldefrag, urljoin, urlsplit

import aiohttp

from argus.core.http import HttpClient, read_limited
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.core.settings import get_settings
from argus.intel.crypto import find_addresses
from argus.intel.pivots import extract_trackers
from argus.modules.base import BaseModule
from argus.modules.discovery.document_metadata import MAX_DOCUMENT, classify_author, parse_document
from argus.modules.discovery.web_recon import INTL_PHONE, TEL_LINK, normalise_phone

MAX_PAGE = 600_000
MAX_LINK_DEPTH = 4
MAX_DOCUMENTS = 10  # documents on the site whose metadata is read
HREF = re.compile(r"""(?:href|src)\s*=\s*["']([^"'<>\s]{1,2000})["']""", re.I)
TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
EMAIL = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b")
OBFUSCATED_EMAIL = re.compile(
    r"\b([A-Za-z0-9._%+-]{1,64})\s*[\[(]\s*at\s*[\])]\s*((?:[A-Za-z0-9-]{1,63}\s*[\[(]\s*dot\s*[\])]\s*)+[A-Za-z]{2,24})\b",
    re.I,
)
DOT = re.compile(r"\s*[\[(]\s*dot\s*[\])]\s*", re.I)
DOCUMENT = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|odt|ods|odp|rtf|csv)$", re.I)
SKIP_PATH = re.compile(r"\.(jpe?g|png|gif|webp|svg|ico|css|js|mjs|woff2?|ttf|eot|mp[34]|mov|avi|zip|gz|rar|7z|exe|dmg|apk|"
                       r"iso|json|xml|txt)$|/(wp-json|feed|cart|checkout|login|logout|wp-admin|admin)(/|$)", re.I)  # fmt: skip
NOT_EMAILS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", "@2x", "@3x", "example.com", "sentry.io",
              "wixpress.com", "domain.com", "email.com", "yourdomain")  # fmt: skip

# host -> (platform, pattern for the account part of the path). Shares and posts are not accounts.
SOCIAL: dict[str, tuple[str, re.Pattern[str]]] = {
    "twitter.com": ("X (Twitter)", re.compile(r"^/(?!share|intent|home|search|hashtag|i/)([A-Za-z0-9_]{1,15})/?$")),
    "x.com": ("X (Twitter)", re.compile(r"^/(?!share|intent|home|search|hashtag|i/)([A-Za-z0-9_]{1,15})/?$")),
    "facebook.com": ("Facebook", re.compile(r"^/(?!sharer|share|dialog|plugins|tr|events/|groups/)([A-Za-z0-9.\-]{2,80})/?$")),
    "instagram.com": ("Instagram", re.compile(r"^/(?!p/|reel/|explore/)([A-Za-z0-9_.]{1,30})/?$")),
    "linkedin.com": ("LinkedIn", re.compile(r"^/((?:in|company)/[A-Za-z0-9\-_%]{2,100})/?$")),
    "youtube.com": ("YouTube", re.compile(r"^/((?:@|c/|channel/|user/)[A-Za-z0-9_\-.]{2,100})/?$")),
    "tiktok.com": ("TikTok", re.compile(r"^/(@[A-Za-z0-9_.]{2,24})/?$")),
    "t.me": ("Telegram", re.compile(r"^/(?!share/)([A-Za-z0-9_]{5,32})/?$")),
    "github.com": ("GitHub", re.compile(r"^/(?!sponsors/|orgs/|features|about)([A-Za-z0-9\-]{1,39})/?$")),
    "wa.me": ("WhatsApp", re.compile(r"^/(\d{8,15})/?$")),
    "pinterest.com": ("Pinterest", re.compile(r"^/(?!pin/)([A-Za-z0-9_]{3,30})/?$")),
    "threads.net": ("Threads", re.compile(r"^/(@[A-Za-z0-9_.]{1,30})/?$")),
    "bsky.app": ("Bluesky", re.compile(r"^/profile/([A-Za-z0-9.\-]{3,253})/?$")),
    "patreon.com": ("Patreon", re.compile(r"^/(?!posts/|join/)([A-Za-z0-9_]{2,64})/?$")),
    "gofundme.com": ("GoFundMe", re.compile(r"^/(f/[A-Za-z0-9\-]{3,120})/?$")),
    "paypal.me": ("PayPal", re.compile(r"^/([A-Za-z0-9]{1,30})/?$")),
}  # fmt: skip


def _site(host: str) -> str:
    return host.lower().removeprefix("www.")


def social_account(url: str) -> tuple[str, str, str] | None:
    """(platform, account, canonical URL) for a link to a social media account; None for anything else."""
    parts = urlsplit(url)
    host = _site(parts.hostname or "").removeprefix("m.").removeprefix("mobile.")
    if host not in SOCIAL:
        return None
    platform, pattern = SOCIAL[host]
    match = pattern.match(parts.path or "/")
    if not match:
        return None
    account = match.group(1).rstrip("/")
    return platform, account, f"https://{host}/{account}"


class RobotRules:
    """The parts of robots.txt that apply to every crawler (``User-agent: *``) or to Argus."""

    def __init__(self, text: str = ""):
        self.disallow: list[str] = []
        self.allow: list[str] = []
        self.sitemaps: list[str] = []
        groups: list[tuple[set[str], list[tuple[str, str]]]] = []
        agents: set[str] = set()
        rules: list[tuple[str, str]] = []
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key, value = key.strip().lower(), value.strip()
            if key == "sitemap":
                self.sitemaps.append(value)
            elif key == "user-agent":
                if rules:
                    groups.append((agents, rules))
                    agents, rules = set(), []
                agents.add(value.lower())
            elif key in ("allow", "disallow"):
                rules.append((key, value))
        if agents or rules:
            groups.append((agents, rules))
        mine = [r for a, r in groups if any("argus" in agent for agent in a)]
        chosen = mine or [r for a, r in groups if "*" in a]
        for group in chosen:
            for key, value in group:
                if value:
                    (self.allow if key == "allow" else self.disallow).append(value)

    @staticmethod
    def _matches(rule: str, path: str) -> bool:
        pattern = "^" + re.escape(rule).replace(r"\*", ".*")
        if pattern.endswith(r"\$"):
            pattern = pattern[:-2] + "$"
        return re.match(pattern, path) is not None

    def allowed(self, path: str) -> bool:
        """The longest matching rule wins; Allow wins a tie (as Google does)."""
        best_allow = max((len(r) for r in self.allow if self._matches(r, path)), default=-1)
        best_disallow = max((len(r) for r in self.disallow if self._matches(r, path)), default=-1)
        return best_disallow < 0 or best_allow >= best_disallow


def page_facts(html: str) -> dict[str, Any]:
    """What one page publishes: emails, phones, wallets, trackers, links."""
    text = unescape(re.sub(r"<[^>]+>", " ", html))
    emails = {m.group(0).lower().strip(".") for m in EMAIL.finditer(unescape(html))}
    for name, domain in OBFUSCATED_EMAIL.findall(text):  # "jane [at] example [dot] org"
        emails.add(f"{name}@{DOT.sub('.', domain)}".lower())
    emails = {e for e in emails if not any(bad in e for bad in NOT_EMAILS) and len(e) <= 254}
    phones: dict[str, float] = {}
    for raw in TEL_LINK.findall(html):
        if number := normalise_phone(raw):
            phones[number] = 0.8  # published as a clickable number
    for raw in INTL_PHONE.findall(text):
        if number := normalise_phone(raw):
            phones.setdefault(number, 0.55)
    title = TITLE.search(html)
    return {
        "title": " ".join(unescape(title.group(1)).split())[:200] if title else "",
        "emails": emails, "phones": phones, "wallets": find_addresses(html, limit=20),
        "trackers": extract_trackers(html), "links": [unescape(h) for h in HREF.findall(html)],
    }  # fmt: skip


class SiteCrawlerModule(BaseModule):
    name = "site_crawler"
    description = "Reads a whole website (obeying robots.txt): emails, phones, wallets, social accounts, documents, IDs"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.DOMAIN, EntityType.SUBDOMAIN]
    attack_techniques = ("T1594",)  # search victim-owned websites
    active = True
    timeout_factor = 4.0  # many pages, deliberately spaced out

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth <= 1 and not entity.metadata.get("out_of_scope")

    async def _fetch(self, session: HttpClient, url: str, config: ScanConfig) -> tuple[int, str, str | None, str]:
        """(status, content type, body or None, redirect location)."""
        timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
        async with session.get(url, timeout=timeout, allow_redirects=False,
                               headers={"Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"}) as resp:  # fmt: skip
            kind = resp.headers.get("Content-Type", "").split(";")[0].strip().lower()
            if resp.status in (301, 302, 303, 307, 308):
                return resp.status, kind, None, resp.headers.get("Location", "")
            if resp.status != 200 or kind not in ("text/html", "application/xhtml+xml", "text/plain", "application/xml",
                                                  "text/xml", ""):  # fmt: skip
                return resp.status, kind, None, ""
            body = await read_limited(resp, MAX_PAGE)
        return 200, kind, body.decode("utf-8", errors="ignore") if body is not None else None, ""

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        settings = get_settings()
        host = entity.value.strip().lower().rstrip(".")
        site = _site(host)
        base = f"https://{host}"
        limit, delay = settings.crawl_max_pages, settings.crawl_delay_seconds

        def on_site(url: str) -> bool:
            parts = urlsplit(url)
            return parts.scheme in ("http", "https") and _site(parts.hostname or "") == site

        robots = RobotRules()
        status, _, body, _ = await self._fetch(session, f"{base}/robots.txt", config)
        if status == 200 and body and "<html" not in body[:500].lower():
            robots = RobotRules(body)
        queue: deque[tuple[str, int]] = deque([(f"{base}/", 0)])
        for sitemap in [*robots.sitemaps[:2], f"{base}/sitemap.xml"][:3]:
            if not on_site(sitemap):
                continue
            status, _, body, _ = await self._fetch(session, sitemap, config)
            if status == 200 and body:
                for loc in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", body)[: limit * 2]:
                    if on_site(loc) and not loc.endswith(".xml"):
                        queue.append((unescape(loc), 1))
        seen: set[str] = set()
        pages: list[dict[str, str]] = []
        blocked: list[str] = []
        found: dict[str, Any] = {"emails": {}, "phones": {}, "wallets": {}, "trackers": {}, "social": {},
                                 "documents": {}, "outbound": {}}  # fmt: skip
        while queue and len(pages) < limit:
            url, link_depth = queue.popleft()
            url = urldefrag(url)[0]
            parts = urlsplit(url)
            key = f"{_site(parts.hostname or '')}{parts.path or '/'}?{parts.query}"
            if key in seen or not on_site(url) or SKIP_PATH.search(parts.path or ""):
                continue
            seen.add(key)
            path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
            if not robots.allowed(path):
                blocked.append(path)
                continue
            if pages:
                await asyncio.sleep(delay)
            try:
                status, _kind, html, location = await self._fetch(session, url, config)
            except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
                self.report_error(host, exc)
                continue
            if location:
                target = urljoin(url, location)
                if on_site(target):
                    queue.appendleft((target, link_depth))
                continue
            if status != 200 or not html:
                continue
            facts = page_facts(html)
            pages.append({"url": url, "title": facts["title"]})
            for email in facts["emails"]:
                found["emails"].setdefault(email, url)
            for number, confidence in facts["phones"].items():
                previous = found["phones"].get(number)
                if previous is None or confidence > previous[0]:
                    found["phones"][number] = (confidence, url)
            for wallet in facts["wallets"]:
                found["wallets"].setdefault(wallet.value, (wallet, url))
            for tracker, product in facts["trackers"].items():
                found["trackers"].setdefault(tracker, product)
            for link in facts["links"]:
                absolute = urldefrag(urljoin(url, link))[0]
                link_parts = urlsplit(absolute)
                if link_parts.scheme not in ("http", "https"):
                    continue
                if on_site(absolute):
                    if DOCUMENT.search(link_parts.path or ""):
                        found["documents"].setdefault(absolute, url)
                    elif link_depth < MAX_LINK_DEPTH:
                        queue.append((absolute, link_depth + 1))
                elif account := social_account(absolute):
                    found["social"].setdefault(account[2], (account[0], account[1], url))
                elif link_parts.hostname:
                    other = _site(link_parts.hostname)
                    if other.removeprefix("m.") not in SOCIAL:  # share buttons are not the site's connections
                        found["outbound"][other] = found["outbound"].get(other, 0) + 1
                    if DOCUMENT.search(link_parts.path or ""):
                        found["documents"].setdefault(absolute, url)
        self.report_ok()
        outbound = sorted(found["outbound"].items(), key=lambda kv: -kv[1])[:30]
        entity.metadata["crawl"] = {
            "pages": len(pages), "limit_reached": len(pages) >= limit and bool(queue),
            "blocked_by_robots": len(blocked), "page_list": pages[:60],
        }  # fmt: skip
        if found["trackers"]:
            entity.metadata["tracking_ids"] = [{"id": t, "product": p} for t, p in found["trackers"].items()][:20]
        if outbound:
            entity.metadata["links_to_sites"] = [{"site": s, "links": n} for s, n in outbound]
        depth = entity.depth + 1

        def published(etype: EntityType, value: str, label: str, confidence: float, page: str, **md: Any) -> Entity:
            return Entity.create(etype, value, label=label, source_module=self.name, confidence=confidence,
                                 depth=depth, metadata={"origin": "published on website", "found_on": page, **md})  # fmt: skip

        for email, page in sorted(found["emails"].items())[:40]:
            own = email.split("@", 1)[1].removeprefix("www.") == site or email.endswith("." + site)
            mail = published(EntityType.EMAIL, email, email, 0.9 if own else 0.75, page, on_site_domain=own)
            yield mail
            yield Relation.create(mail.id, entity.id, RelationType.ASSOCIATED_WITH, label="Published on website")
        for number, (confidence, page) in sorted(found["phones"].items())[:15]:
            phone = published(EntityType.PHONE, number, number, confidence, page)
            yield phone
            yield Relation.create(phone.id, entity.id, RelationType.ASSOCIATED_WITH, label="Published on website")
        for value, (wallet, page) in list(found["wallets"].items())[:20]:
            item = published(EntityType.CRYPTO_WALLET, value, f"{wallet.label} {value[:10]}…", 0.95, page,
                             chain=wallet.chain, traceable=wallet.traceable)  # fmt: skip
            yield item
            yield Relation.create(item.id, entity.id, RelationType.ASSOCIATED_WITH, label="Published on website")
        for url, (platform, account, page) in list(found["social"].items())[:25]:
            profile = published(EntityType.SOCIAL_PROFILE, url, f"{platform}: {account}", 0.85, page,
                                platform=platform, handle=account)  # fmt: skip
            yield profile
            yield Relation.create(entity.id, profile.id, RelationType.HAS_ACCOUNT, label="Linked from website")
        read = 0
        for url, page in list(found["documents"].items())[:30]:
            name = urlsplit(url).path.rsplit("/", 1)[-1] or url
            doc = published(EntityType.URL, url, name, 0.9, page, category="document",
                            live="linked", hosted_elsewhere=not on_site(url))  # fmt: skip
            meta: dict[str, Any] | None = None
            parts = urlsplit(url)
            if on_site(url) and read < MAX_DOCUMENTS and robots.allowed(parts.path or "/"):
                read += 1
                await asyncio.sleep(delay)
                meta = await self._document(session, url, config)
            if meta:
                doc.metadata["document"] = meta
            yield doc
            yield Relation.create(entity.id, doc.id, RelationType.ASSOCIATED_WITH, label="Document offered")
            for author in (meta or {}).get("authors", [])[:3]:
                raw = author.split("\\")[-1]  # DOMAIN\user -> user
                kind = classify_author(raw)
                if kind is None:
                    continue
                person = published(kind, raw, raw, 0.6, page, origin="document metadata", document=url)
                yield person
                yield Relation.create(doc.id, person.id, RelationType.ASSOCIATED_WITH, label="Document author")

    async def _document(self, session: HttpClient, url: str, config: ScanConfig) -> dict[str, Any] | None:
        """Who wrote a document the site offers, and with what (from its hidden metadata)."""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=config.timeout_seconds * 3),
                                   allow_redirects=False) as resp:  # fmt: skip
                if resp.status != 200:
                    return None
                data = await read_limited(resp, MAX_DOCUMENT)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return None
        if not data:
            return None
        try:
            return parse_document(data) or None
        except Exception:
            return None
