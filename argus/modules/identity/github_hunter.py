"""Deep GitHub OSINT: public commit email unmasking, SSH keys, and identity correlation."""

from __future__ import annotations

import logging
import re
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import aiohttp

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.github_hunter")


class GitHubHunterModule(BaseModule):
    """Mines GitHub public events, git commit metadata, and profiles to unmask identity attributes."""

    name = "github_hunter"
    description = "GitHub intelligence: extracts commit author emails, real names, SSH keys, and organizations"
    supported_entity_types = [EntityType.USERNAME]
    attack_techniques = ("T1593.003", "T1589.002", "T1589.003")

    async def run(
        self,
        entity: Entity,
        session: HttpClient,
        config: ScanConfig,
    ) -> AsyncIterator[Entity | Relation]:
        username = entity.value.strip()
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "Argus-OSINT/1.0",
        }
        timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)

        # 1. User Profile Lookup
        profile_url = f"https://api.github.com/users/{username}"
        try:
            async with session.get(profile_url, headers=headers, timeout=timeout) as resp:
                if resp.status == 200:
                    user_data = await resp.json()

                    # Real Name -> Person entity
                    real_name = user_data.get("name")
                    if real_name and len(real_name.strip()) > 1:
                        person_entity = Entity.create(
                            entity_type=EntityType.PERSON,
                            value=real_name.strip(),
                            label=real_name.strip(),
                            metadata={"origin": "github_profile", "username": username},
                            source_module=self.name,
                            confidence=0.98,
                            depth=entity.depth + 1,
                        )
                        yield person_entity
                        yield Relation.create(
                            source_id=entity.id,
                            target_id=person_entity.id,
                            rel_type=RelationType.BELONGS_TO,
                            label="Real Name",
                        )

                    # Company -> Organization entity
                    company = user_data.get("company")
                    if company:
                        clean_comp = company.strip().lstrip("@")
                        if clean_comp:
                            org_entity = Entity.create(
                                entity_type=EntityType.ORGANIZATION,
                                value=clean_comp,
                                label=clean_comp,
                                metadata={"source": "github_company"},
                                source_module=self.name,
                                confidence=0.9,
                                depth=entity.depth + 1,
                            )
                            yield org_entity
                            yield Relation.create(
                                source_id=entity.id,
                                target_id=org_entity.id,
                                rel_type=RelationType.ASSOCIATED_WITH,
                                label="Affiliated Organization",
                            )

                    # Personal Blog / Website -> Domain entity
                    blog = user_data.get("blog")
                    if blog:
                        # "https://site.com/blog" -> "site.com": a domain entity must be a bare hostname
                        clean_blog = (urlsplit(blog if "://" in blog else f"http://{blog}").hostname or "").lower()
                        if clean_blog and "." in clean_blog:
                            domain_entity = Entity.create(
                                entity_type=EntityType.DOMAIN,
                                value=clean_blog,
                                label=clean_blog,
                                metadata={"source": "github_blog"},
                                source_module=self.name,
                                confidence=0.95,
                                depth=entity.depth + 1,
                            )
                            yield domain_entity
                            yield Relation.create(
                                source_id=entity.id,
                                target_id=domain_entity.id,
                                rel_type=RelationType.ASSOCIATED_WITH,
                                label="Personal Website",
                            )

                    # Twitter Handle -> Social Profile
                    twitter = user_data.get("twitter_username")
                    if twitter:
                        tw_url = f"https://twitter.com/{twitter}"
                        tw_entity = Entity.create(
                            entity_type=EntityType.SOCIAL_PROFILE,
                            value=tw_url,
                            label=f"Twitter: @{twitter}",
                            metadata={"platform": "Twitter", "handle": twitter},
                            source_module=self.name,
                            confidence=0.98,
                            depth=entity.depth + 1,
                        )
                        yield tw_entity
                        yield Relation.create(
                            source_id=entity.id,
                            target_id=tw_entity.id,
                            rel_type=RelationType.HAS_ACCOUNT,
                            label="Linked Twitter Handle",
                        )
        except Exception as e:
            logger.debug("GitHub profile query failed for %s: %s", username, e)

        # 2. Public Events & Commit Email Unmasking (Legendary OSINT technique)
        events_url = f"https://api.github.com/users/{username}/events/public"
        found_emails: set[str] = set()

        try:
            async with session.get(events_url, headers=headers, timeout=timeout) as resp:
                if resp.status == 200:
                    events = await resp.json()
                    if isinstance(events, list):
                        for ev in events:
                            if ev.get("type") == "PushEvent":
                                commits = ev.get("payload", {}).get("commits", [])
                                for commit in commits:
                                    author = commit.get("author", {})
                                    email = author.get("email", "").strip().lower()
                                    # Ignore GitHub anonymous noreply emails
                                    if (
                                        email
                                        and "noreply.github.com" not in email
                                        and re.match(r"^[^@]+@[^@]+\.[^@]+$", email)
                                    ):
                                        found_emails.add(email)
        except Exception as e:
            logger.debug("GitHub events mining failed for %s: %s", username, e)

        for email_addr in list(found_emails)[:3]:
            email_entity = Entity.create(
                entity_type=EntityType.EMAIL,
                value=email_addr,
                label=email_addr,
                metadata={"origin": "git_commit_metadata", "username": username},
                source_module=self.name,
                confidence=0.95,
                depth=entity.depth + 1,
            )
            yield email_entity
            yield Relation.create(
                source_id=entity.id,
                target_id=email_entity.id,
                rel_type=RelationType.BELONGS_TO,
                label="Commit Author Email",
            )
