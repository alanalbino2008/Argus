"""Deeper sources about a person: the same picture elsewhere, deleted accounts, old "about" pages and documents.

* ``reverse_image``: where a confirmed profile picture appears on the web (TinEye: your own key or
  Argus Connect credits). The same picture on another account is strong evidence of the same person,
  even under another name. This matches the *same picture*, never a face.
* ``archived_accounts``: for a username, whether the Internet Archive kept copies of that profile on
  the big networks, so accounts deleted or renamed years ago are found again.
* ``site_history``: for a personal website, the archived copies of its "about", CV and contact pages,
  which often listed an address, other accounts or an earlier job.
* ``person_documents``: CVs and other documents found by web search: the author, company and dates
  hidden in the file, and the email addresses and links in it. The Internet Archive's copy is read when
  there is one; the site itself is asked only outside anonymous cases.

None of these contacts the person or signs in anywhere.
"""

from __future__ import annotations

import html
import io
import re
import zipfile
import zlib
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from defusedxml import ElementTree as SafeET

from argus.accounts.connect_client import available, lookup
from argus.accounts.connectors import ConnectError
from argus.core.http import HttpClient, read_limited
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule
from argus.modules.discovery.document_metadata import MAX_DOCUMENT, parse_document
from argus.modules.identity.web_mentions import social_profile

CDX = "https://web.archive.org/cdx/search/cdx"
EMAIL_RE = re.compile(rb"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,190}\.[A-Za-z]{2,24}")
URL_RE = re.compile(rb"https?://[A-Za-z0-9./?=_%&:#@+~-]{4,300}")
STREAM = re.compile(rb"stream\r?\n(.*?)\r?\nendstream", re.S)
NOT_PERSONAL = ("example.", "sentry.", "w3.org", "schema.org", "wixpress", "noreply", "no-reply", "@2x", ".png", ".jpg")


def _emails(data: bytes) -> list[str]:
    out = []
    for raw in EMAIL_RE.findall(data):
        address = raw.decode("ascii", "ignore").lower().strip(".")
        if not any(bad in address for bad in NOT_PERSONAL) and address not in out:
            out.append(address)
    return out[:10]


def _links(data: bytes) -> list[str]:
    out = []
    for raw in URL_RE.findall(data):
        url = html.unescape(raw.decode("ascii", "ignore")).rstrip(").,;'\"")
        url = re.sub(r"^https?://web\.archive\.org/web/\d+[a-z_]*/", "", url)
        if url not in out:
            out.append(url)
    return out[:50]


# ---------------------------------------------------------------------------- the same picture elsewhere
class ReverseImageModule(BaseModule):
    name = "reverse_image"
    description = "Where a confirmed profile picture appears on the web (TinEye): other accounts and pages using it"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.URL]
    third_party_safe = True  # TinEye fetches the picture; the person's sites never see Argus
    attack_techniques = ("T1593",)

    @classmethod
    def is_configured(cls) -> bool:
        return available("tineye")

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth == 0 and entity.value.startswith("https://")

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        if not (config.hints or {}).get("image_search"):
            return  # only for profile pictures sent by a person search, never for any URL scanned
        try:
            data = await lookup(session, "tineye", "search", {"image_url": entity.value})
        except ConnectError as exc:
            self.report_error("tineye", exc.detail)
            return
        results = data.get("results") or {}
        rows = results.get("matches") if isinstance(results, dict) else results
        pages: list[tuple[str, str | None, str | None]] = []
        pages.extend(
            (str(link["backlink"]), match.get("domain"), str(link.get("crawl_date") or "")[:10] or None)
            for match in rows or []
            for link in (match.get("backlinks") or [])[:5]
            if link.get("backlink")
        )
        entity.metadata["image_matches"] = len(pages)
        seen: set[str] = set()
        for url, domain, crawled in pages[:30]:
            found = social_profile(url)
            value = found[1] if found else url
            if value in seen:
                continue
            seen.add(value)
            if found:
                item = Entity.create(EntityType.SOCIAL_PROFILE, value, label=f"{found[0]}: {value.rsplit('/', 1)[-1]}",
                                     source_module=self.name, confidence=0.8, depth=entity.depth + 1,
                                     metadata={"platform": found[0], "same_picture": True, "first_seen": crawled,
                                               "origin": "uses the same picture (reverse image search)"})  # fmt: skip
            else:
                item = Entity.create(EntityType.URL, value, source_module=self.name, confidence=0.7, depth=entity.depth + 1,
                                     metadata={"category": "image_match", "same_picture": True, "domain": domain,
                                               "first_seen": crawled, "out_of_scope": True,
                                               "origin": "uses the same picture (reverse image search)"})  # fmt: skip
            yield item
            yield Relation.create(entity.id, item.id, RelationType.ASSOCIATED_WITH, confidence=0.8,
                                  label="Same picture")  # fmt: skip


# ---------------------------------------------------------------------------- deleted and renamed accounts
ARCHIVED_PLATFORMS: dict[str, tuple[str, str]] = {  # platform: (address to ask the archive about, address shown)
    "X": ("twitter.com/{}", "https://x.com/{}"),
    "Instagram": ("instagram.com/{}/", "https://www.instagram.com/{}"),
    "Facebook": ("facebook.com/{}", "https://www.facebook.com/{}"),
    "TikTok": ("tiktok.com/@{}", "https://www.tiktok.com/@{}"),
    "Reddit": ("reddit.com/user/{}", "https://www.reddit.com/user/{}"),
    "YouTube": ("youtube.com/@{}", "https://www.youtube.com/@{}"),
    "Tumblr": ("{}.tumblr.com/", "https://{}.tumblr.com"),
    "Pinterest": ("pinterest.com/{}/", "https://www.pinterest.com/{}"),
    "Medium": ("medium.com/@{}", "https://medium.com/@{}"),
    "Flickr": ("flickr.com/people/{}/", "https://www.flickr.com/people/{}"),
    "SoundCloud": ("soundcloud.com/{}", "https://soundcloud.com/{}"),
    "DeviantArt": ("deviantart.com/{}", "https://www.deviantart.com/{}"),
    "Twitch": ("twitch.tv/{}", "https://www.twitch.tv/{}"),
    "VK": ("vk.com/{}", "https://vk.com/{}"),
    "LiveJournal": ("{}.livejournal.com/", "https://{}.livejournal.com"),
    "Myspace": ("myspace.com/{}", "https://myspace.com/{}"),
    "Telegram": ("t.me/{}", "https://t.me/{}"),
    "GitHub": ("github.com/{}", "https://github.com/{}"),
}


def _date(stamp: str) -> str:
    return f"{stamp[:4]}-{stamp[4:6]}" if len(stamp) >= 6 else stamp


class ArchivedAccountsModule(BaseModule):
    name = "archived_accounts"
    description = (
        "Accounts with a username that the Internet Archive kept copies of, including deleted and renamed ones"
    )
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.USERNAME]
    third_party_safe = True
    attack_techniques = ("T1593",)
    rate_limits: ClassVar[dict[str, float]] = {"web.archive.org": 1.0}

    def can_handle(self, entity: Entity) -> bool:
        return (super().can_handle(entity) and entity.depth == 0
                and re.fullmatch(r"[A-Za-z0-9._-]{2,40}", entity.value.strip().lstrip("@")) is not None)  # fmt: skip

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        handle = entity.value.strip().lstrip("@")
        found: dict[str, dict[str, Any]] = {}
        for platform, (asked, shown) in ARCHIVED_PLATFORMS.items():
            if platform in ("Tumblr", "LiveJournal") and not re.fullmatch(r"[A-Za-z0-9-]{2,40}", handle):
                continue
            url = (f"{CDX}?url={quote(asked.format(handle), safe='')}&output=json&fl=timestamp,statuscode"
                   "&filter=statuscode:200&collapse=timestamp:6&limit=300")  # fmt: skip
            async with session.get(url) as resp:
                if resp.status != 200:
                    continue
                rows = await resp.json()
            stamps = [r[0] for r in (rows or [])[1:] if isinstance(r, list) and r and str(r[0]).isdigit()]
            if not stamps:
                continue
            found[platform] = {"first": _date(stamps[0]), "last": _date(stamps[-1]), "months": len(stamps),
                               "archive_url": f"https://web.archive.org/web/{stamps[-1]}/{asked.format(handle)}"}  # fmt: skip
            profile = Entity.create(
                EntityType.SOCIAL_PROFILE, shown.format(handle), label=f"{platform}: {handle} (archived)",
                source_module=self.name, confidence=0.6, depth=entity.depth + 1,
                metadata={"platform": platform, "archived": found[platform],
                          "origin": f"archived copies {found[platform]['first']} to {found[platform]['last']}"},
            )  # fmt: skip
            yield profile
            yield Relation.create(entity.id, profile.id, RelationType.HAS_ACCOUNT, confidence=0.6,
                                  label=f"Archived {platform} profile")  # fmt: skip
        entity.metadata["archived_accounts"] = found


# ---------------------------------------------------------------------------- a personal website's old pages
ABOUT_PATH = re.compile(r"/(about|about-me|aboutme|bio|cv|resume|curriculum|contact|contact-me|me|profile|team)"
                        r"(\.html?|\.php|/)?$", re.I)  # fmt: skip
MAX_PAGES = 4


class SiteHistoryModule(BaseModule):
    name = "site_history"
    description = (
        "Archived 'about', CV and contact pages of a personal website: addresses, accounts and jobs once listed"
    )
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.DOMAIN]
    third_party_safe = True
    attack_techniques = ("T1593", "T1594")
    rate_limits: ClassVar[dict[str, float]] = {"web.archive.org": 1.0}

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth == 0

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        domain = entity.value.strip().lower()
        url = (f"{CDX}?url={quote(domain, safe='')}/*&output=json&fl=original,timestamp&filter=statuscode:200"
               "&filter=mimetype:text/html&collapse=urlkey&limit=3000")  # fmt: skip
        async with session.get(url) as resp:
            if resp.status != 200:
                return
            rows = await resp.json()
        pages: dict[str, tuple[str, str]] = {}
        for row in (rows or [])[1:]:
            if not isinstance(row, list) or len(row) < 2:
                continue
            original, stamp = str(row[0]), str(row[1])
            path = urlsplit(original if "//" in original else f"http://{original}").path.rstrip("/") or "/"
            match = ABOUT_PATH.search(path)
            if match and match.group(1).lower() not in pages:
                pages[match.group(1).lower()] = (original, stamp)
        read = []
        seen: set[str] = set()
        for kind, (original, stamp) in list(pages.items())[:MAX_PAGES]:
            async with session.get(f"https://web.archive.org/web/{stamp}id_/{original}") as resp:
                if resp.status != 200:
                    continue
                body = (await resp.text(errors="ignore"))[:500_000].encode("utf-8", "ignore")
            when = _date(stamp)
            read.append({"page": kind, "date": when, "archive_url": f"https://web.archive.org/web/{stamp}/{original}"})
            origin = f"archived '{kind}' page of {domain} ({when})"
            for address in _emails(body):
                if address in seen:
                    continue
                seen.add(address)
                mail = Entity.create(EntityType.EMAIL, address, source_module=self.name, confidence=0.75,
                                     depth=entity.depth + 1, metadata={"origin": origin})  # fmt: skip
                yield mail
                yield Relation.create(entity.id, mail.id, RelationType.ASSOCIATED_WITH, label=f"Listed on {kind} page")
            for link in _links(body):
                found = social_profile(link)
                if not found or found[1] in seen:
                    continue
                seen.add(found[1])
                profile = Entity.create(EntityType.SOCIAL_PROFILE, found[1], label=f"{found[0]}: {found[1].rsplit('/', 1)[-1]}",
                                        source_module=self.name, confidence=0.75, depth=entity.depth + 1,
                                        metadata={"platform": found[0], "origin": origin,
                                                  "profile": {"links": [f"https://{domain}"]}})  # fmt: skip
                yield profile
                yield Relation.create(
                    entity.id, profile.id, RelationType.ASSOCIATED_WITH, label=f"Linked on {kind} page"
                )
        entity.metadata["site_history"] = read


# ---------------------------------------------------------------------------- documents found about the person
DOC_PATH = re.compile(r"\.(pdf|docx?|odt|rtf)$", re.I)


def document_text(data: bytes) -> bytes:
    """The readable text of a document, as far as it can be read without a full parser: the text of a
    Word file, or a PDF's (decompressed) content streams. Used only to find addresses and links."""
    if data.startswith(b"PK"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                info = z.getinfo("word/document.xml")
                if info.file_size > 5_000_000:
                    return b""
                root = SafeET.fromstring(z.read(info))
                return " ".join(t.text or "" for t in root.iter() if t.tag.endswith("}t")).encode()
        except Exception:
            return b""
    chunks = [data[:2_000_000]]
    for i, match in enumerate(STREAM.finditer(data)):
        if i >= 200:
            break
        try:
            chunks.append(zlib.decompressobj().decompress(match.group(1), 1_000_000))
        except zlib.error:
            continue
    return b" ".join(chunks)


class PersonDocumentsModule(BaseModule):
    name = "person_documents"
    description = (
        "CVs and documents found by web search: hidden author, company and dates, and the addresses and links in them"
    )
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.URL]
    enrichment = True  # documents are found at a person search's depth limit
    attack_techniques = ("T1593",)
    rate_limits: ClassVar[dict[str, float]] = {"web.archive.org": 1.0, "archive.org": 1.0}

    def can_handle(self, entity: Entity) -> bool:
        return (super().can_handle(entity) and entity.depth <= 1 and entity.metadata.get("category") == "mention"
                and DOC_PATH.search(urlsplit(entity.value).path or "") is not None)  # fmt: skip

    async def _fetch(self, session: HttpClient, url: str, passive: bool) -> tuple[bytes | None, str]:
        async with session.get(f"https://archive.org/wayback/available?url={quote(url, safe='')}") as resp:
            data = await resp.json() if resp.status == 200 else {}
        closest = ((data or {}).get("archived_snapshots") or {}).get("closest") or {}
        if closest.get("available") and closest.get("timestamp"):
            async with session.get(f"https://web.archive.org/web/{closest['timestamp']}id_/{url}") as resp:
                if resp.status == 200:
                    body = await read_limited(resp, MAX_DOCUMENT)
                    return body, "the Internet Archive's copy" if body is not None else "larger than 15 MB"
        if passive:
            return None, "not archived (an anonymous case does not fetch it from the site)"
        async with session.get(url) as resp:
            if resp.status != 200:
                return None, f"HTTP {resp.status}"
            body = await read_limited(resp, MAX_DOCUMENT)
            return body, "the site" if body is not None else "larger than 15 MB"

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        data, source = await self._fetch(session, entity.value, config.passive_only)
        if not data:
            entity.metadata["document"] = {"read": False, "why": source}
            return
        facts = parse_document(data)
        text = document_text(data)
        emails = _emails(text)
        links = [u for u in _links(text) if social_profile(u)]
        entity.metadata["document"] = {"read": True, "from": source, **facts, "emails": emails, "links": links[:10]}
        for address in emails[:5]:
            mail = Entity.create(EntityType.EMAIL, address, source_module=self.name, confidence=0.6, depth=entity.depth + 1,
                                 metadata={"origin": f"in a document ({entity.value})"})  # fmt: skip
            yield mail
            yield Relation.create(entity.id, mail.id, RelationType.ASSOCIATED_WITH, label="Written in the document")
