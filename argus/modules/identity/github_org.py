"""Domain -> GitHub organisation -> its public members (staff handles).

Many companies run a GitHub organisation, and staff who make their membership
public reveal their personal handles - which Argus then hunts across 100+ sites and
enriches like any other identity. To avoid false matches, an organisation is used
only when its own profile points back to the target: its website or public email
is on the target domain (``verified_domain`` is also recorded when GitHub itself
verified the domain).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import quote, urlsplit

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.core.settings import get_settings
from argus.modules.base import BaseModule

API = "https://api.github.com"
MAX_CANDIDATES = 5
MAX_MEMBERS = 60


def org_matches(org: dict[str, Any], domain: str) -> bool:
    blog = (org.get("blog") or "").strip()
    host = (urlsplit(blog if "://" in blog else f"https://{blog}").hostname or "").lower() if blog else ""
    email = (org.get("email") or "").lower()
    return host == domain or host.endswith("." + domain) or email.endswith("@" + domain)


def github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    token = get_settings().github_token
    if token:  # optional: raises GitHub's rate limit from 60 to 5,000 requests/hour
        headers["Authorization"] = f"Bearer {token.get_secret_value()}"
    return headers


class GitHubOrgModule(BaseModule):
    name = "github_org"
    description = "Finds the target's GitHub organisation (verified against the domain) and its public members"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.DOMAIN]
    attack_techniques = ("T1593.003", "T1589.003")
    rate_limits: ClassVar[dict[str, float]] = {"api.github.com": 1.0}

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth <= 1

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        domain = entity.value.strip().lower().removeprefix("www.")
        label = domain.split(".")[0]
        headers = github_headers()
        async with session.get(
            f"{API}/search/users?q={quote(label)}+type:org&per_page={MAX_CANDIDATES}", headers=headers
        ) as resp:
            if resp.status != 200:
                self.report_error("github-search", f"HTTP {resp.status}")
                return
            candidates = [i["login"] for i in (await resp.json()).get("items", []) if i.get("login")]

        for login in candidates:
            async with session.get(f"{API}/orgs/{quote(login)}", headers=headers) as resp:
                if resp.status != 200:
                    continue
                org = await resp.json()
            if not org_matches(org, domain):
                continue
            async for item in self._emit(entity, org, session, headers):
                yield item
            return  # one verified organisation is enough

    async def _emit(
        self, entity: Entity, org: dict[str, Any], session: HttpClient, headers: dict[str, str]
    ) -> AsyncIterator[Entity | Relation]:
        login = org["login"]
        depth = entity.depth + 1
        profile = Entity.create(
            EntityType.SOCIAL_PROFILE,
            f"https://github.com/{login}",
            label=f"GitHub org: {login}",
            metadata={
                "platform": "GitHub",
                "username": login,
                "account_type": "organization",
                "verified": True,
                "verified_domain": bool(org.get("is_verified")),
                "profile": {
                    k: v
                    for k, v in {
                        "display_name": org.get("name"),
                        "bio": org.get("description"),
                        "location": org.get("location"),
                        "website": org.get("blog"),
                        "public_email": org.get("email"),
                        "created_at": org.get("created_at"),
                        "public_repos": org.get("public_repos"),
                        "followers": org.get("followers"),
                    }.items()
                    if v not in (None, "")
                },
            },
            source_module=self.name,
            confidence=0.95,
            depth=depth,
        )
        yield profile
        yield Relation.create(entity.id, profile.id, RelationType.OPERATES, label="GitHub organisation")

        async with session.get(f"{API}/orgs/{quote(login)}/public_members?per_page=100", headers=headers) as resp:
            members = await resp.json() if resp.status == 200 else []
        profile.metadata["public_members"] = len(members)
        for member in members[:MAX_MEMBERS]:
            handle = member.get("login")
            if not handle:
                continue
            user = Entity.create(
                EntityType.USERNAME,
                handle,
                label=handle,
                metadata={"origin": f"public member of GitHub org {login}", "organization": login},
                source_module=self.name,
                confidence=0.9,
                depth=depth + 1,
            )
            yield user
            yield Relation.create(user.id, profile.id, RelationType.BELONGS_TO, label="Public member")
