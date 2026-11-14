"""Profile enrichment: turn "an account exists" into "what this account reveals".

For every social profile found, query the platform's *official public API* (never
scraping behind logins) and extract what the person has chosen to publish:
display name, bio, location, website, employer, account age, public email and -
most valuable for identity resolution - **linked accounts**:

* Keybase proofs are cryptographically signed statements that the same person
  controls a Twitter/GitHub/Reddit account or a website;
* Mastodon profile links marked ``verified_at`` are confirmed with ``rel="me"``.

Verified links become new ``username`` pivots (high confidence). Merely *claimed*
links are recorded as profiles but not hunted further, which keeps the graph
focused on solid evidence.

Confidence reflects how trustworthy each fact is: a self-declared display name or
location is weaker than a cryptographic proof.
"""

from __future__ import annotations

import html
import logging
import re
from collections.abc import AsyncIterator, Callable
from datetime import datetime, timezone
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.profile_enricher")

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
TAG_RE = re.compile(r"<[^>]+>")

# Keybase proof types -> profile URL templates.
PROOF_URLS = {
    "twitter": "https://twitter.com/{}",
    "github": "https://github.com/{}",
    "reddit": "https://www.reddit.com/user/{}",
    "hackernews": "https://news.ycombinator.com/user?id={}",
    "mastodon": "https://{}",
}
PLATFORM_HOSTS = {
    "twitter.com": "Twitter",
    "x.com": "Twitter",
    "github.com": "GitHub",
    "gitlab.com": "GitLab",
    "www.reddit.com": "Reddit",
    "reddit.com": "Reddit",
    "news.ycombinator.com": "HackerNews",
    "keybase.io": "Keybase",
    "dev.to": "Dev.to",
    "mastodon.social": "Mastodon.social",
    "www.linkedin.com": "LinkedIn",
    "linkedin.com": "LinkedIn",
    "bsky.app": "Bluesky",
}


def strip_html(text: str | None) -> str:
    return html.unescape(TAG_RE.sub(" ", text or "")).strip()


def _iso(value: Any) -> str | None:
    """Accept ISO strings or unix timestamps; return an ISO date string."""
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    return str(value)


def _host(url: str | None) -> str | None:
    if not url:
        return None
    host = urlsplit(url if "://" in url else f"https://{url}").hostname
    return host.lower() if host and "." in host else None


def _is_real_name(name: str | None, handle: str) -> bool:
    if not name:
        return False
    n = name.strip()
    return 3 <= len(n) <= 60 and " " in n and n.lower() != handle.lower() and not any(c.isdigit() for c in n)


def _facts(**kwargs: Any) -> dict[str, Any]:
    return {k: v for k, v in kwargs.items() if v not in (None, "", [], {})}


# --------------------------------------------------------------------- per-platform extractors
# Each returns normalised facts:
#   display_name, bio, location, website, company, created_at, followers, public_email,
#   avatar_url, links: [{"url", "platform", "handle", "verified"}]


async def _gitlab(session: HttpClient, handle: str) -> dict[str, Any] | None:
    async with session.get(f"https://gitlab.com/api/v4/users?username={quote(handle)}") as resp:
        if resp.status != 200:
            return None
        users = await resp.json()
    if not users:
        return None
    async with session.get(f"https://gitlab.com/api/v4/users/{users[0]['id']}") as resp:
        user = await resp.json() if resp.status == 200 else users[0]
    links = []
    if user.get("twitter"):
        links.append(
            {
                "url": f"https://twitter.com/{user['twitter']}",
                "platform": "Twitter",
                "handle": user["twitter"],
                "verified": False,
            }
        )
    if user.get("linkedin"):
        links.append(
            {
                "url": f"https://www.linkedin.com/in/{user['linkedin']}",
                "platform": "LinkedIn",
                "handle": user["linkedin"],
                "verified": False,
            }
        )
    return _facts(
        display_name=user.get("name"),
        bio=user.get("bio"),
        location=user.get("location"),
        website=user.get("website_url"),
        company=user.get("organization"),
        created_at=user.get("created_at"),
        public_email=user.get("public_email"),
        avatar_url=user.get("avatar_url"),
        links=links,
    )


async def _reddit(session: HttpClient, handle: str) -> dict[str, Any] | None:
    async with session.get(f"https://www.reddit.com/user/{quote(handle)}/about.json") as resp:
        if resp.status != 200:
            return None
        data = (await resp.json()).get("data", {})
    sub = data.get("subreddit") or {}
    return _facts(
        display_name=sub.get("title"),
        bio=sub.get("public_description"),
        created_at=_iso(data.get("created_utc")),
        followers=data.get("total_karma"),
        avatar_url=(data.get("icon_img") or "").split("?")[0] or None,
    )


async def _hackernews(session: HttpClient, handle: str) -> dict[str, Any] | None:
    async with session.get(f"https://hacker-news.firebaseio.com/v0/user/{quote(handle)}.json") as resp:
        if resp.status != 200:
            return None
        user = await resp.json()
    if not user:
        return None
    about = strip_html(user.get("about"))
    links = [
        {
            "url": u.rstrip(".,"),
            "platform": PLATFORM_HOSTS.get(_host(u) or "", "Website"),
            "handle": None,
            "verified": False,
        }
        for u in URL_RE.findall(html.unescape(user.get("about") or ""))
    ]
    return _facts(bio=about, created_at=_iso(user.get("created")), followers=user.get("karma"), links=links)


async def _keybase(session: HttpClient, handle: str) -> dict[str, Any] | None:
    url = f"https://keybase.io/_/api/1.0/user/lookup.json?usernames={quote(handle)}&fields=profile,proofs_summary"
    async with session.get(url) as resp:
        if resp.status != 200:
            return None
        them = (await resp.json()).get("them") or []
    if not them or not them[0]:
        return None
    user = them[0]
    profile = user.get("profile") or {}
    links = []
    website = None
    for proof in (user.get("proofs_summary") or {}).get("all", []):
        kind, name = proof.get("proof_type"), proof.get("nametag")
        if not name:
            continue
        if kind in ("dns", "generic_web_site"):
            website = website or proof.get("service_url") or f"https://{name}"
            links.append(
                {
                    "url": proof.get("service_url") or f"https://{name}",
                    "platform": "Website",
                    "handle": name,
                    "verified": True,
                }
            )
        elif kind in PROOF_URLS:
            links.append(
                {
                    "url": PROOF_URLS[kind].format(name),
                    "platform": kind.capitalize() if kind != "hackernews" else "HackerNews",
                    "handle": name,
                    "verified": True,
                }
            )
    return _facts(
        display_name=profile.get("full_name"),
        bio=profile.get("bio"),
        location=profile.get("location"),
        website=website,
        links=links,
    )


async def _devto(session: HttpClient, handle: str) -> dict[str, Any] | None:
    async with session.get(f"https://dev.to/api/users/by_username?url={quote(handle)}") as resp:
        if resp.status != 200:
            return None
        user = await resp.json()
    links = []
    if user.get("twitter_username"):
        links.append(
            {
                "url": f"https://twitter.com/{user['twitter_username']}",
                "platform": "Twitter",
                "handle": user["twitter_username"],
                "verified": False,
            }
        )
    if user.get("github_username"):
        links.append(
            {
                "url": f"https://github.com/{user['github_username']}",
                "platform": "GitHub",
                "handle": user["github_username"],
                "verified": False,
            }
        )
    return _facts(
        display_name=user.get("name"),
        bio=user.get("summary"),
        location=user.get("location"),
        website=user.get("website_url"),
        created_at=user.get("joined_at"),
        avatar_url=user.get("profile_image"),
        links=links,
    )


async def _mastodon(session: HttpClient, handle: str) -> dict[str, Any] | None:
    async with session.get(f"https://mastodon.social/api/v1/accounts/lookup?acct={quote(handle)}") as resp:
        if resp.status != 200:
            return None
        acct = await resp.json()
    links = [
        {
            "url": u,
            "platform": PLATFORM_HOSTS.get(_host(u) or "", "Website"),
            "handle": None,
            "verified": bool(f.get("verified_at")),  # Mastodon confirmed the link with rel="me"
        }
        for f in acct.get("fields") or []
        for u in URL_RE.findall(html.unescape(f.get("value") or ""))
    ]
    return _facts(
        display_name=acct.get("display_name"),
        bio=strip_html(acct.get("note")),
        created_at=acct.get("created_at"),
        followers=acct.get("followers_count"),
        avatar_url=acct.get("avatar"),
        links=links,
    )


async def _dockerhub(session: HttpClient, handle: str) -> dict[str, Any] | None:
    async with session.get(f"https://hub.docker.com/v2/users/{quote(handle)}/") as resp:
        if resp.status != 200:
            return None
        user = await resp.json()
    return _facts(
        display_name=user.get("full_name"),
        location=user.get("location"),
        company=user.get("company"),
        website=user.get("profile_url"),
        created_at=user.get("date_joined"),
    )


async def _bluesky(session: HttpClient, handle: str) -> dict[str, Any] | None:
    actor = handle if "." in handle else f"{handle}.bsky.social"
    async with session.get(f"https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={quote(actor)}") as resp:
        if resp.status != 200:
            return None
        p = await resp.json()
    return _facts(
        display_name=p.get("displayName"),
        bio=p.get("description"),
        created_at=p.get("createdAt"),
        followers=p.get("followersCount"),
        avatar_url=p.get("avatar"),
    )


EXTRACTORS: dict[str, Callable[[HttpClient, str], Any]] = {
    "GitLab": _gitlab,
    "Reddit": _reddit,
    "HackerNews": _hackernews,
    "Keybase": _keybase,
    "Dev.to": _devto,
    "Mastodon.social": _mastodon,
    "DockerHub": _dockerhub,
    "Bluesky": _bluesky,
}


class ProfileEnricherModule(BaseModule):
    name = "profile_enricher"
    description = (
        "Extracts public profile details (name, bio, location, website, linked accounts) via official platform APIs"
    )
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.SOCIAL_PROFILE]
    enrichment = True
    attack_techniques = ("T1593.001", "T1589.003", "T1591.001")

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.metadata.get("platform") in EXTRACTORS

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        platform = entity.metadata["platform"]
        handle = entity.metadata.get("username") or entity.value.rstrip("/").rsplit("/", 1)[-1].split("=")[-1]
        facts = await EXTRACTORS[platform](session, handle)
        if not facts:
            return
        entity.metadata["profile"] = {
            k: (v[:400] if isinstance(v, str) else v) for k, v in facts.items() if k != "links"
        }
        depth = entity.depth + 1

        def make(etype: EntityType, value: str, label: str, confidence: float, **md: Any) -> Entity:
            return Entity.create(
                etype,
                value,
                label=label,
                metadata={"source_platform": platform, **md},
                source_module=self.name,
                confidence=confidence,
                depth=depth,
            )

        def link(target: Entity, rel: RelationType, label: str) -> Relation:
            return Relation.create(entity.id, target.id, rel, label=label, metadata={"platform": platform})

        if _is_real_name(facts.get("display_name"), handle):
            person = make(
                EntityType.PERSON,
                facts["display_name"].strip(),
                facts["display_name"].strip(),
                0.6,
                origin="self-declared display name",
            )
            yield person
            yield Relation.create(entity.id, person.id, RelationType.BELONGS_TO, label=f"Display name on {platform}")

        location = (facts.get("location") or "").strip()
        if 2 <= len(location) <= 80:
            place = make(EntityType.LOCATION, location, location, 0.5, origin="self-declared")
            yield place
            yield link(place, RelationType.LOCATED_IN, "Declared location")

        company = (facts.get("company") or "").strip().lstrip("@")
        if 2 <= len(company) <= 100:
            org = make(EntityType.ORGANIZATION, company, company, 0.6, origin="self-declared employer")
            yield org
            yield link(org, RelationType.ASSOCIATED_WITH, "Declared employer")

        host = _host(facts.get("website"))
        if host and host not in PLATFORM_HOSTS:
            site = make(EntityType.DOMAIN, host, host, 0.8, origin="profile website")
            yield site
            yield link(site, RelationType.ASSOCIATED_WITH, "Personal website")

        emails = {e.lower() for e in EMAIL_RE.findall(f"{facts.get('public_email', '')} {facts.get('bio', '')}")}
        for addr in sorted(emails)[:5]:
            mail = make(EntityType.EMAIL, addr, addr, 0.85, origin="published on profile")
            yield mail
            yield link(mail, RelationType.ASSOCIATED_WITH, "Public email")

        unique: dict[str, dict[str, Any]] = {}
        for item in facts.get("links") or []:  # the same URL often appears in both href and text
            key = item["url"].rstrip("/").lower()
            if key not in unique or (item.get("verified") and not unique[key].get("verified")):
                unique[key] = item
        emitted_domains = {host} if host and host not in PLATFORM_HOSTS else set()
        for item in list(unique.values())[:10]:
            verified = bool(item.get("verified"))
            linked_host = _host(item["url"])
            if item["platform"] == "Website":
                if linked_host and linked_host not in PLATFORM_HOSTS and linked_host not in emitted_domains:
                    emitted_domains.add(linked_host)
                    site = make(
                        EntityType.DOMAIN,
                        linked_host,
                        linked_host,
                        0.95 if verified else 0.7,
                        origin="verified link" if verified else "linked website",
                    )
                    yield site
                    yield link(
                        site, RelationType.ASSOCIATED_WITH, "Verified website" if verified else "Links to website"
                    )
                continue
            other = make(
                EntityType.SOCIAL_PROFILE,
                item["url"],
                f"{item['platform']}: {item.get('handle') or item['url']}",
                0.95 if verified else 0.6,
                platform=item["platform"],
                username=item.get("handle"),
                verified=verified,
            )
            yield other
            yield link(other, RelationType.ASSOCIATED_WITH, "Verified same owner" if verified else "Links to")
            if verified and item.get("handle"):  # proven identity: worth hunting this handle elsewhere
                alias = make(
                    EntityType.USERNAME, item["handle"], item["handle"], 0.95, origin=f"verified via {platform}"
                )
                yield alias
                yield Relation.create(other.id, alias.id, RelationType.BELONGS_TO, label="Handle")
