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
import json
import re
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.intel.avatars import fetch_fingerprint
from argus.modules.base import BaseModule
from argus.modules.identity.web_mentions import display_name, social_profile

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


NEXT_DATA = re.compile(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', re.S)
SNAP_FILLER = re.compile(r"\s*is on Snapchat!?\s*$", re.I)


def snapchat_profile(page: str, handle: str) -> dict[str, Any] | None:
    """The profile Snapchat embeds in its page (name, bio, website, picture, subscribers); the preview tags
    only carry filler ("… is on Snapchat!") and a screenshot of the page."""
    match = NEXT_DATA.search(page)
    if not match:
        return None
    try:
        data = json.loads(match.group(1))
    except ValueError:
        return None
    profile = ((data.get("props") or {}).get("pageProps") or {}).get("userProfile") or {}
    info = profile.get("publicProfileInfo") or profile.get("userInfo") or {}
    if not isinstance(info, dict) or str(info.get("username") or "").lower() != handle.lower():
        return None
    raw_bitmoji = info.get("bitmoji3d")
    bitmoji: dict[str, Any] = raw_bitmoji if isinstance(raw_bitmoji, dict) else {}
    picture = info.get("profilePictureUrl") or (bitmoji.get("avatarImage") or {}).get("url")
    return {"display_name": str(info.get("title") or info.get("displayName") or "").strip(),
            "bio": str(info.get("bio") or "").strip()[:500], "website": str(info.get("websiteUrl") or "").strip(),
            "location": str(info.get("address") or "").strip(), "avatar_url": picture or None,
            "followers": info.get("subscriberCount") or None}  # fmt: skip


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
    if platform == "Snapchat":
        embedded = snapchat_profile(page, handle)
        if embedded is not None:
            return embedded
    low = title.lower()
    if not title or any(w in low for w in WALL_WORDS) or handle.lower() not in (low + tags.get("og:url", "").lower()):
        return None
    if platform == "Snapchat":  # the preview tags only: no real bio, and the image is a page screenshot
        name = re.sub(r"\s+on Snapchat$", "", title).strip()
        return {"display_name": name, "bio": "", "avatar_url": None}
    return {"display_name": display_name(title) or title[:80], "bio": tags.get("og:description", "")[:500],
            "avatar_url": tags.get("og:image")}  # fmt: skip


TG_POST = re.compile(
    r'<div class="tgme_widget_message [^"]*js-widget_message" data-post="([^"]+)"(.*?)(?=<div class="tgme_widget_message_wrap|\Z)',
    re.S,
)
TG_TEXT = re.compile(r'<div class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>', re.S)
TG_TIME = re.compile(r'<time datetime="([^"]+)"')
TG_COUNTER = re.compile(r'<span class="counter_value">([^<]+)</span> <span class="counter_type">subscribers')
TG_HREF = re.compile(r'href="(https?://[^"]+)"')
TG_MENTION = re.compile(r"(?<![\w@])@([A-Za-z][A-Za-z0-9_]{4,31})\b")
MAX_POSTS = 20


def _plain(fragment: str) -> str:
    text = re.sub(r"<br\s*/?>", "\n", fragment)
    return html.unescape(re.sub(r"<[^>]+>", "", text)).strip()


def telegram_channel(page: str, handle: str) -> dict[str, Any] | None:
    """A public channel's recent posts, as ``t.me/s/<channel>`` shows them to anyone."""
    posts: list[dict[str, Any]] = []
    for post_id, body in TG_POST.findall(page):
        if not post_id.lower().startswith(handle.lower() + "/"):
            continue  # a forwarded post shown in the channel: someone else's
        text = TG_TEXT.search(body)
        when = TG_TIME.search(body)
        plain = _plain(text.group(1)) if text else ""
        links = (
            [h for h in dict.fromkeys(TG_HREF.findall(text.group(1))) if not h.startswith("https://t.me/" + handle)]
            if text
            else []
        )
        posts.append({"url": f"https://t.me/{post_id}", "date": when.group(1) if when else None, "text": plain[:500],
                      "links": links[:10], "mentions": sorted(set(TG_MENTION.findall(plain)))[:10]})  # fmt: skip
    if not posts:
        return None
    posts = posts[-MAX_POSTS:]
    dates: list[str] = sorted(str(p["date"]) for p in posts if p["date"])
    hours: dict[int, int] = {}
    for d in dates:
        hours[int(d[11:13])] = hours.get(int(d[11:13]), 0) + 1
    counter = TG_COUNTER.search(page)
    return {"subscribers": counter.group(1) if counter else None, "posts": posts, "first_shown": dates[0] if dates else None,
            "last_post": dates[-1] if dates else None, "post_hours_utc": dict(sorted(hours.items())),
            "links": list(dict.fromkeys(link for p in posts for link in p["links"]))[:30],
            "mentions": sorted({m for p in posts for m in p["mentions"]})[:30]}  # fmt: skip


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
                if platform == "Telegram":
                    async for item in self._channel(session, handle, entity):
                        yield item
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
            if platform == "Telegram":
                async for item in self._channel(session, handle, profile):
                    yield item
        entity.metadata["social_pages"] = checked

    async def _channel(self, session: HttpClient, handle: str, profile: Entity) -> AsyncIterator[Entity | Relation]:
        """A public Telegram channel's recent posts: when it posts, what it links to, whom it mentions.
        A person's own account has no such page (t.me/s/ shows posts only for public channels)."""
        try:
            async with session.get(f"https://t.me/s/{quote(handle)}", headers={"Accept-Language": "en"}) as resp:
                if resp.status != 200:
                    return
                page = await resp.text(errors="ignore")
        except Exception:
            return
        channel = telegram_channel(page[:2_000_000], handle)
        if channel is None:
            return
        profile.metadata["telegram_channel"] = channel
        for link in channel["links"]:
            found = social_profile(link)
            if found is None or found[0] == "Telegram":
                continue  # other channels' posts linked or forwarded: news, not their accounts
            platform, url = found
            linked = Entity.create(EntityType.SOCIAL_PROFILE, url, label=f"{platform}: {url.rsplit('/', 1)[-1]}",
                                   source_module=self.name, confidence=0.6, depth=profile.depth + 1,
                                   metadata={"platform": platform, "origin": "linked in their Telegram channel",
                                             "profile": {"links": [profile.value]}})  # fmt: skip
            yield linked
            yield Relation.create(profile.id, linked.id, RelationType.ASSOCIATED_WITH, confidence=0.6,
                                  label="Linked in their Telegram channel")  # fmt: skip
