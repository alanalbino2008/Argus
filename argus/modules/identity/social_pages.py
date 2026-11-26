"""The big social networks, as anyone sees them without an account.

Instagram, Facebook, Threads, TikTok, Snapchat, YouTube, Telegram and Pinterest each serve a public
page for a profile, with the name it shows, a short description and the profile picture in the
page's preview tags (the ones link previews use). This module reads that page for a username, and
for profiles found by other means (for example a web search), and keeps:

* whether the profile exists, and the **name** and **bio** it shows;
* its **profile picture**, fingerprinted so it can be matched with a known photo or other accounts.

What is not public stays out: Argus never signs in, never uses an account or cookies, and does not
read posts, friends or followers. A network that only shows a sign-in page (as Facebook and Instagram
often do, and X and LinkedIn always do) is recorded as "sign-in wall": those profiles are found
through the web search (``web_mentions``) instead. Google accounts have no public profile page to
read; their public parts are a YouTube channel (read here) and the address's Gravatar and keys.
"""

from __future__ import annotations

import html
import re
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.intel.avatars import fetch_fingerprint
from argus.modules.base import BaseModule
from argus.modules.identity.web_mentions import display_name

# platform: (profile address for a handle, host)
PAGES: dict[str, tuple[str, str]] = {
    "Instagram": ("https://www.instagram.com/{}/", "instagram.com"),
    "Facebook": ("https://www.facebook.com/{}", "facebook.com"),
    "Threads": ("https://www.threads.net/@{}", "threads.net"),
    "TikTok": ("https://www.tiktok.com/@{}", "tiktok.com"),
    "Snapchat": ("https://www.snapchat.com/add/{}", "snapchat.com"),
    "YouTube": ("https://www.youtube.com/@{}", "youtube.com"),
    "Telegram": ("https://t.me/{}", "t.me"),
    "Pinterest": ("https://www.pinterest.com/{}/", "pinterest.com"),
}
WALL_WORDS = ("log in", "login", "sign up", "sign in", "log into", "join facebook", "create an account")
META_RE = re.compile(r"<meta\s+([^>]+)>", re.I)
ATTR_RE = re.compile(r"""(property|name|content)\s*=\s*["']([^"']*)["']""", re.I)
TG_TITLE = re.compile(r'<div class="tgme_page_title"[^>]*>\s*<span[^>]*>([^<]+)</span>', re.I)


def meta_tags(page: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for attrs in META_RE.findall(page):
        found = {k.lower(): v for k, v in ATTR_RE.findall(attrs)}
        key = (found.get("property") or found.get("name") or "").lower()
        if key and "content" in found:
            out.setdefault(key, html.unescape(found["content"]).strip())
    return out


def read_page(platform: str, handle: str, page: str) -> dict[str, Any] | None:
    """What a public profile page shows, or None when it is not this profile (a sign-in wall, a
    "page not found", or another page)."""
    tags = meta_tags(page)
    title = tags.get("og:title") or tags.get("twitter:title") or ""
    if platform == "Telegram":
        match = TG_TITLE.search(page)
        if not match or "tgme_page_extra" not in page:
            return None  # t.me answers every handle with a page; a real one has these
        title = html.unescape(match.group(1)).strip()
        return {"display_name": title, "bio": tags.get("og:description", "")[:500], "avatar_url": tags.get("og:image")}
    low = title.lower()
    if not title or any(w in low for w in WALL_WORDS) or handle.lower() not in (low + tags.get("og:url", "").lower()):
        return None
    return {"display_name": display_name(title) or title[:80], "bio": tags.get("og:description", "")[:500],
            "avatar_url": tags.get("og:image")}  # fmt: skip


def platform_of(url: str) -> tuple[str, str] | None:
    """(platform, handle) for a profile address on one of these networks."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().removeprefix("www.").removeprefix("m.")
    segments = [s for s in parts.path.split("/") if s]
    for platform, (_pattern, domain) in PAGES.items():
        if host != domain or not segments:
            continue
        first = segments[1] if platform == "Snapchat" and segments[0] == "add" and len(segments) > 1 else segments[0]
        handle = first.lstrip("@")
        if re.fullmatch(r"[A-Za-z0-9._-]{2,40}", handle):
            return platform, handle
    return None


class SocialPagesModule(BaseModule):
    name = "social_pages"
    description = ("Public profile pages on Instagram, Facebook, Threads, TikTok, Snapchat, YouTube, Telegram and "
                   "Pinterest: the name, bio and picture they show without signing in")  # fmt: skip
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.USERNAME, EntityType.SOCIAL_PROFILE]
    enrichment = True  # also for profiles found at a search's depth limit (e.g. by web search)
    attack_techniques = ("T1593.001",)
    rate_limits: ClassVar[dict[str, float]] = {"www.instagram.com": 2.0, "www.facebook.com": 2.0, "www.threads.net": 2.0,
                                               "www.tiktok.com": 2.0, "www.snapchat.com": 1.0, "www.youtube.com": 1.0,
                                               "t.me": 1.0, "www.pinterest.com": 1.0}  # fmt: skip

    def can_handle(self, entity: Entity) -> bool:
        if not super().can_handle(entity) or entity.depth > 1:
            return False
        if entity.type == EntityType.SOCIAL_PROFILE:
            return platform_of(entity.value) is not None and not (entity.metadata.get("profile") or {}).get(
                "avatar_url"
            )
        return re.fullmatch(r"[A-Za-z0-9._-]{2,40}", entity.value.strip().lstrip("@")) is not None

    async def _read(self, session: HttpClient, platform: str, handle: str) -> tuple[str, dict[str, Any] | None]:
        url = PAGES[platform][0].format(quote(handle))
        try:
            async with session.get(url, headers={"Accept": "text/html", "Accept-Language": "en"}) as resp:
                if resp.status == 404:
                    return "not found", None
                if resp.status != 200:
                    return ("sign-in wall" if resp.status in (401, 403, 429, 999) else f"HTTP {resp.status}"), None
                page = await resp.text(errors="ignore")
        except Exception as exc:
            return f"unreachable ({type(exc).__name__})", None
        facts = read_page(platform, handle, page[:400_000])
        if facts is None:
            wall = any(w in page[:50_000].lower() for w in ("loginform", "login_form", "/accounts/login", "log in"))
            return ("sign-in wall" if wall else "not found"), None
        return "found", facts

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        if entity.type == EntityType.SOCIAL_PROFILE:
            found = platform_of(entity.value)
            if found is None:
                return
            platform, handle = found
            status, facts = await self._read(session, platform, handle)
            entity.metadata["public_page"] = status
            if facts:
                profile = entity.metadata.setdefault("profile", {})
                for key, value in facts.items():
                    if value and not profile.get(key):
                        profile[key] = value
                if not entity.metadata.get("avatar_hash"):
                    entity.metadata["avatar_hash"] = await fetch_fingerprint(session, facts.get("avatar_url"))
            return
        handle = entity.value.strip().lstrip("@")
        checked: dict[str, str] = {}
        for platform in PAGES:
            status, facts = await self._read(session, platform, handle)
            checked[platform] = status
            if not facts:
                continue
            url = PAGES[platform][0].format(handle).rstrip("/")
            profile = Entity.create(
                EntityType.SOCIAL_PROFILE, url, label=f"{platform}: {handle}", source_module=self.name,
                confidence=0.85, depth=entity.depth + 1,
                metadata={"platform": platform, "profile": {k: v for k, v in facts.items() if v},
                          "avatar_hash": await fetch_fingerprint(session, facts.get("avatar_url")),
                          "origin": "public profile page", "public_page": "found"},
            )  # fmt: skip
            yield profile
            yield Relation.create(entity.id, profile.id, RelationType.HAS_ACCOUNT, label=f"{platform} profile")
        entity.metadata["social_pages"] = checked
