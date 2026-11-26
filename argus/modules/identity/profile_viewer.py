"""Public profiles behind sign-in walls, through a profile-viewing service (SocialFetch).

LinkedIn, X, Facebook and Instagram show automated visitors a sign-in page instead of a public
profile, although the same profile is public: anyone can see it in a browser without an account.
A profile-viewing service reads it from its own servers, as a logged-out visitor would, and returns
what the page shows. With the investigator's own SocialFetch key (``ARGUS_SOCIALFETCH_API_KEY`` or
Settings → Your API keys), Argus asks it for:

* **profiles found** on LinkedIn, X, Facebook and Instagram that Argus could not read itself (found
  by web search, linked from another profile, or typed in as a known detail);
* **a username's** X, Instagram and Facebook profiles (the handle is usually the same).

It keeps what the profile shows publicly: name, headline or bio, location, website, picture (for
photo matching), follower count, and for LinkedIn the current and past positions and education.
Private and "not public" profiles are recorded as such; nothing is guessed.

**What it never asks for**: contact details (the service's email and phone "finders"), followers,
following lists, stories or posts. Those go beyond what a profile shows its visitors.

Each lookup costs SocialFetch credits (LinkedIn 5, the others 1), at most
``ARGUS_SOCIALFETCH_MAX_LOOKUPS`` per scan (20). The service sees what is looked up (the profile
address), as a web search engine would; the person's sites never see Argus.
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
from argus.core.settings import get_settings
from argus.intel.avatars import fetch_fingerprint
from argus.modules.base import BaseModule

PROVIDER = "socialfetch"
HOSTS = {"linkedin.com": "LinkedIn", "x.com": "X", "twitter.com": "X", "facebook.com": "Facebook",
         "instagram.com": "Instagram"}  # fmt: skip
OPERATION = {"LinkedIn": "linkedin", "X": "x", "Facebook": "facebook", "Instagram": "instagram"}
FROM_USERNAME = ("X", "Instagram", "Facebook")
PROFILE_URL = {
    "X": "https://x.com/{}",
    "Instagram": "https://www.instagram.com/{}",
    "Facebook": "https://www.facebook.com/{}",
}
NOT_PROFILES = {"in", "share", "sharer", "sharer.php", "intent", "home", "login", "search", "explore", "p", "reel",
                "pages", "groups", "events", "watch", "hashtag", "i", "profile.php", "people"}  # fmt: skip


def target_of(url: str) -> tuple[str, dict[str, str]] | None:
    """(platform, lookup parameters) for a profile address on a walled network, else None."""
    parts = urlsplit(url)
    host = (parts.hostname or "").lower().removeprefix("www.").removeprefix("m.")
    host = "linkedin.com" if host.endswith(".linkedin.com") else host
    platform = HOSTS.get(host)
    segments = [s for s in parts.path.split("/") if s]
    if platform is None or not segments:
        return None
    if platform == "LinkedIn":
        if len(segments) < 2 or segments[0] != "in" or not re.fullmatch(r"[A-Za-z0-9_-]{3,100}", segments[1]):
            return None
        return platform, {"handle": segments[1]}
    handle = segments[0].lstrip("@")
    if handle.lower() in NOT_PROFILES or not re.fullmatch(r"[A-Za-z0-9._-]{1,100}", handle):
        return None
    if platform == "Facebook":
        return platform, {"url": f"https://www.facebook.com/{handle}"}
    return platform, {"handle" if platform == "X" else "profile": handle}


def _text(value: Any) -> str:
    return str(value or "").strip()


def facts_from(platform: str, data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    """(lookup status, profile facts) from the service's answer."""
    inner = data.get("data")
    body: dict[str, Any] = inner if isinstance(inner, dict) else data
    status = _text(body.get("lookupStatus")) or ("not_found" if data.get("not_found") else "found")
    if status != "found":
        return status, {}
    if platform == "LinkedIn":
        p = body.get("profile") or {}
        current = [x for x in p.get("currentPositions") or p.get("positions") or [] if isinstance(x, dict)]

        def org(x: dict[str, Any]) -> str:
            return _text((x.get("organization") or {}).get("name") or x.get("organizationName"))

        positions = [f"{_text(x.get('title'))} at {org(x)}".strip() for x in (p.get("positions") or [])[:8]
                     if isinstance(x, dict)]  # fmt: skip
        schools = [_text(e.get("schoolName") or (e.get("school") or {}).get("name") or e.get("title"))
                   for e in (p.get("education") or [])[:5] if isinstance(e, dict)]  # fmt: skip
        geo = p.get("geo") or {}
        return status, {
            "display_name": _text(p.get("fullName")) or f"{_text(p.get('firstName'))} {_text(p.get('lastName'))}".strip(),
            "bio": " ".join(x for x in (_text(p.get("headline")), _text(p.get("summary"))[:600]) if x),
            "location": _text(p.get("location")) or _text(geo.get("full")),
            "company": ", ".join(dict.fromkeys(o for o in (org(x) for x in current[:3]) if o)),
            "positions": [x for x in positions if x and x != "at"], "education": [s for s in schools if s],
            "avatar_url": p.get("profilePictureUrl"), "followers": p.get("followerCount"),
        }  # fmt: skip
    p = body.get("profile") or {}
    metrics = p.get("metrics") or body.get("metrics") or {}
    contact = p.get("contact") or {}
    website = p.get("website") or p.get("externalUrl") or contact.get("website")
    return status, {
        "display_name": _text(p.get("displayName")), "bio": _text(p.get("bio") or (p.get("business") or {}).get("intro")),
        "location": _text(p.get("location")), "website": _text(website), "avatar_url": p.get("avatarUrl"),
        "followers": metrics.get("followers"), "verified": bool(p.get("verified") or p.get("blueVerified")),
        "public_email": _text(contact.get("email")), "public_phone": _text(contact.get("phone")),
    }  # fmt: skip


class ProfileViewerModule(BaseModule):
    name = "profile_viewer"
    description = ("Public LinkedIn, X, Facebook and Instagram profiles that show automated visitors a sign-in "
                   "page, read by SocialFetch as a logged-out visitor (your own key; costs its credits)")  # fmt: skip
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.SOCIAL_PROFILE, EntityType.USERNAME]
    third_party_safe = True  # the service fetches the page; the person's sites never see Argus
    enrichment = True
    attack_techniques = ("T1593.001",)

    def __init__(self) -> None:
        super().__init__()
        self.spent = 0

    @classmethod
    def is_configured(cls) -> bool:
        return available(PROVIDER)

    def can_handle(self, entity: Entity) -> bool:
        if not super().can_handle(entity) or entity.depth > 1:
            return False
        if entity.type == EntityType.USERNAME:
            return entity.depth == 0 and re.fullmatch(r"@?[A-Za-z0-9._-]{2,40}", entity.value.strip()) is not None
        if target_of(entity.value) is None:
            return False
        return (
            not (entity.metadata.get("profile") or {}).get("avatar_url")
            or entity.metadata.get("public_page") != "found"
        )

    def _budget(self) -> bool:
        return self.spent < get_settings().socialfetch_max_lookups

    async def _look(self, session: HttpClient, platform: str, params: dict[str, str]) -> tuple[str, dict[str, Any]]:
        self.spent += 1
        try:
            answer = await lookup(session, PROVIDER, OPERATION[platform], params)
        except ConnectError as exc:
            self.report_error(PROVIDER, exc.detail)
            return ("no credits" if exc.status == 402 else "error"), {}
        return facts_from(platform, answer)

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        if entity.type == EntityType.SOCIAL_PROFILE:
            found = target_of(entity.value)
            if found is None or not self._budget():
                return
            platform, params = found
            status, facts = await self._look(session, platform, params)
            entity.metadata["viewed_profile"] = {"status": status, "via": "SocialFetch"}
            if facts:
                profile = entity.metadata.setdefault("profile", {})
                for key, value in facts.items():
                    if value not in (None, "", []) and not profile.get(key):
                        profile[key] = value
                entity.metadata["public_page"] = "found"
                if not entity.metadata.get("avatar_hash"):
                    entity.metadata["avatar_hash"] = await fetch_fingerprint(session, facts.get("avatar_url"))
                entity.confidence = max(entity.confidence, 0.85)
            return
        handle = entity.value.strip().lstrip("@")
        checked: dict[str, str] = {}
        for platform in FROM_USERNAME:
            if not self._budget():
                checked[platform] = "not checked (lookup limit for this scan)"
                continue
            url = PROFILE_URL[platform].format(handle)
            status, facts = await self._look(session, platform, target_of(url)[1])  # type: ignore[index]
            checked[platform] = status
            if not facts:
                continue
            profile = Entity.create(
                EntityType.SOCIAL_PROFILE, url, label=f"{platform}: {handle}", source_module=self.name,
                confidence=0.85, depth=entity.depth + 1,
                metadata={"platform": platform, "profile": {k: v for k, v in facts.items() if v not in (None, "", [])},
                          "avatar_hash": await fetch_fingerprint(session, facts.get("avatar_url")),
                          "origin": "public profile (viewed by SocialFetch)", "public_page": "found"},
            )  # fmt: skip
            yield profile
            yield Relation.create(entity.id, profile.id, RelationType.HAS_ACCOUNT, label=f"{platform} profile")
        entity.metadata["viewed_profiles"] = checked
