"""Public Git history: who an email address commits as, which addresses a developer commits with,
and the time zone their computer is set to.

Every Git commit records its author's name, email address and the local time with its UTC offset
(``Date: Tue, 3 Jan 2023 21:14:05 +0100``). Public repositories publish all of that. So:

* from an **email address**: GitHub's public commit search finds commits authored with it, and so
  the GitHub accounts that made them (and the name the person commits under);
* from a **username**: the commits in their own public repositories give the addresses and names
  they commit with (GitHub's private ``noreply`` addresses are skipped), and the UTC offsets of those
  commits give the time zones they work in, which helps tell namesakes apart.

Everything comes from public repositories through GitHub's public API; nothing is sent to the person.
A GitHub token (``ARGUS_GITHUB_TOKEN``) raises GitHub's limit from 60 to 5,000 requests an hour.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import quote

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule
from argus.modules.identity.github_org import github_headers

API = "https://api.github.com"
MAX_REPOS = 5
MAX_COMMITS = 30
MAX_PATCHES = 6
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DATE_RE = re.compile(r"^Date: .*? ([+-])(\d\d)(\d\d)\s*$", re.M)


def usable_email(address: str | None) -> bool:
    address = (address or "").strip().lower()
    return bool(EMAIL_RE.match(address)) and "noreply" not in address and not address.endswith(".local")


def offset_from_patch(text: str) -> str | None:
    """The author's UTC offset (e.g. "+01:00") from a commit in ``git format-patch`` form."""
    match = DATE_RE.search(text)
    return f"{match.group(1)}{match.group(2)}:{match.group(3)}" if match else None


def timezone_summary(offsets: list[str]) -> dict[str, Any] | None:
    if not offsets:
        return None
    counts = Counter(offsets)
    usual, seen = counts.most_common(1)[0]
    return {"usual_offset": usual, "share": round(seen / len(offsets), 2), "offsets": dict(counts),
            "commits": len(offsets), "source": "Git commit times"}  # fmt: skip


class GitIdentityModule(BaseModule):
    name = "git_identity"
    description = ("Public Git history: the GitHub accounts an email address commits as, the addresses a "
                   "developer commits with, and their usual time zone")  # fmt: skip
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.EMAIL, EntityType.USERNAME]
    third_party_safe = True
    attack_techniques = ("T1593.003", "T1589.002")
    rate_limits: ClassVar[dict[str, float]] = {"api.github.com": 1.0, "github.com": 1.0}

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth <= 1

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        if entity.type == EntityType.EMAIL:
            async for item in self._from_email(entity, session):
                yield item
        else:
            async for item in self._from_username(entity, session):
                yield item

    async def _from_email(self, entity: Entity, session: HttpClient) -> AsyncIterator[Entity | Relation]:
        address = entity.value.strip().lower()
        if not usable_email(address):
            return
        url = f"{API}/search/commits?q={quote(f'author-email:{address}')}&per_page=30"
        async with session.get(url, headers=github_headers()) as resp:
            if resp.status != 200:
                if resp.status not in (404, 422):
                    self.report_error("github", f"HTTP {resp.status}")
                return
            data = await resp.json()
        logins: Counter[str] = Counter()
        names: Counter[str] = Counter()
        for item in (data or {}).get("items") or []:
            author = item.get("author") or {}
            if author.get("login"):
                logins[author["login"]] += 1
            name = ((item.get("commit") or {}).get("author") or {}).get("name")
            if name:
                names[name] += 1
        entity.metadata["git_commits"] = {"found": int((data or {}).get("total_count") or 0),
                                          "names": [n for n, _ in names.most_common(3)]}  # fmt: skip
        for login, count in logins.most_common(3):
            profile = Entity.create(
                EntityType.SOCIAL_PROFILE, f"https://github.com/{login}", label=f"GitHub: {login}",
                source_module=self.name, confidence=0.9, depth=entity.depth + 1,
                metadata={"platform": "GitHub", "origin": "verified: commits authored with this address",
                          "commits_with_address": count,
                          "profile": {"display_name": names.most_common(1)[0][0] if names else ""}},
            )  # fmt: skip
            yield profile
            yield Relation.create(entity.id, profile.id, RelationType.HAS_ACCOUNT, confidence=0.9,
                                  label=f"Commits authored with this address ({count})")  # fmt: skip

    async def _from_username(self, entity: Entity, session: HttpClient) -> AsyncIterator[Entity | Relation]:
        login = entity.value.strip().lstrip("@")
        if not re.fullmatch(r"[A-Za-z0-9-]{1,39}", login):
            return
        url = f"{API}/users/{quote(login)}/repos?type=owner&sort=pushed&per_page=20"
        async with session.get(url, headers=github_headers()) as resp:
            if resp.status != 200:
                return
            repos = await resp.json()
        own = [r for r in repos or [] if isinstance(r, dict) and not r.get("fork")][:MAX_REPOS]
        emails: Counter[str] = Counter()
        names: Counter[str] = Counter()
        shas: list[tuple[str, str]] = []
        for repo in own:
            full = repo.get("full_name")
            if not full:
                continue
            curl = f"{API}/repos/{full}/commits?author={quote(login)}&per_page={MAX_COMMITS}"
            async with session.get(curl, headers=github_headers()) as resp:
                if resp.status != 200:
                    continue
                commits = await resp.json()
            for c in commits or []:
                author = (c.get("commit") or {}).get("author") or {}
                if usable_email(author.get("email")):
                    emails[author["email"].strip().lower()] += 1
                if author.get("name"):
                    names[author["name"]] += 1
                if c.get("sha") and len(shas) < MAX_PATCHES:
                    shas.append((full, c["sha"]))
        offsets = []
        for full, sha in shas:
            async with session.get(f"https://github.com/{full}/commit/{sha}.patch") as resp:
                if resp.status == 200:
                    offset = offset_from_patch(await resp.text())
                    if offset:
                        offsets.append(offset)
        zone = timezone_summary(offsets)
        if zone:
            entity.metadata["timezone"] = zone
            account = Entity.create(EntityType.SOCIAL_PROFILE, f"https://github.com/{login}", label=f"GitHub: {login}",
                                    source_module=self.name, confidence=0.9, depth=entity.depth + 1,
                                    metadata={"platform": "GitHub", "timezone": zone})  # fmt: skip
            yield account
            yield Relation.create(entity.id, account.id, RelationType.HAS_ACCOUNT, label="Commits from this account")
        if names:
            entity.metadata["git_names"] = [n for n, _ in names.most_common(3)]
        for address, count in emails.most_common(5):
            mail = Entity.create(EntityType.EMAIL, address, source_module=self.name, confidence=0.9,
                                 depth=entity.depth + 1,
                                 metadata={"origin": "git_commit_metadata", "username": login, "commits": count})  # fmt: skip
            yield mail
            yield Relation.create(entity.id, mail.id, RelationType.BELONGS_TO, confidence=0.9,
                                  label=f"Commits with this address ({count})")  # fmt: skip
