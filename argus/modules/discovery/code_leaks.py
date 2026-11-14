"""Public code that mentions the target: leaked secrets, internal hostnames, staff emails.

Developers paste config files, scripts and test fixtures into public repositories.
GitHub's code search finds every public file mentioning the domain; Argus scans the
matched fragments for credential patterns (cloud keys, tokens, private keys,
passwords) and for internal hostnames and email addresses.

Secrets are **never stored**: only their type, a 4-character preview and length are
kept - enough to identify and rotate them. Requires ``ARGUS_GITHUB_TOKEN`` because
GitHub only allows code search for authenticated users.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import quote

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule
from argus.modules.identity.github_org import github_headers

API = "https://api.github.com/search/code?q={}&per_page=50"
MAX_FILES = 25

SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitLab token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("Slack token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b")),
    ("SendGrid key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
    ("JSON Web Token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    (
        "Connection string",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]{3,}@"),
    ),
    (
        "Password assignment",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|auth[_-]?token)\b\s*[:=]\s*['\"]?([^\s'\"<>{}$]{6,})"
        ),
    ),
]
PLACEHOLDERS = re.compile(
    r"(?i)^(x+|\*+|changeme|password\d*|example|sample|test|dummy|your[_-]?\w*|null|none|true|false)$"
)


def redact(value: str) -> str:
    return f"{value[:4]}… ({len(value)} chars)"


def find_secrets(text: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(1) if kind == "Password assignment" else match.group(0)
            if kind == "Password assignment" and PLACEHOLDERS.match(value):
                continue
            found.append({"type": kind, "preview": "PRIVATE KEY" if kind == "Private key" else redact(value)})
    unique = {(f["type"], f["preview"]): f for f in found}
    return list(unique.values())[:10]


class CodeLeaksModule(BaseModule):
    name = "code_leaks"
    description = "Public GitHub code mentioning the domain: leaked secrets, internal hostnames, emails"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.DOMAIN]
    attack_techniques = ("T1593.003",)
    requires_settings = ("github_token",)
    rate_limits: ClassVar[dict[str, float]] = {"api.github.com": 2.5}  # code search: 30 requests/minute

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth <= 1

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        domain = entity.value.strip().lower()
        headers = {**github_headers(), "Accept": "application/vnd.github.text-match+json"}
        async with session.get(API.format(quote(f'"{domain}"')), headers=headers) as resp:
            if resp.status != 200:
                self.report_error("github-code-search", f"HTTP {resp.status}")
                return
            data = await resp.json()

        host_re = re.compile(r"\b((?:[a-z0-9-]+\.)+" + re.escape(domain) + r")\b", re.I)
        email_re = re.compile(r"\b[A-Za-z0-9._%+-]+@" + re.escape(domain) + r"\b", re.I)
        entity.metadata["public_code"] = {"files": data.get("total_count", 0)}
        depth = entity.depth + 1
        hosts: set[str] = set()
        emails: set[str] = set()
        leaked = 0
        for item in data.get("items", [])[:MAX_FILES]:
            text = "\n".join(m.get("fragment", "") for m in item.get("text_matches", []))
            secrets = find_secrets(text)
            file_hosts = {h.lower() for h in host_re.findall(text)}
            hosts |= file_hosts
            emails |= {e.lower() for e in email_re.findall(text)}
            if not secrets and not file_hosts:
                continue
            leaked += bool(secrets)
            repo: dict[str, Any] = item.get("repository") or {}
            found = Entity.create(
                EntityType.URL,
                item.get("html_url") or f"https://github.com/{repo.get('full_name')}/blob/HEAD/{item.get('path')}",
                label=f"{repo.get('full_name')}/{item.get('path')}"[:90],
                metadata={
                    "category": "code",
                    "origin": "public code",
                    "repository": repo.get("full_name"),
                    "path": item.get("path"),
                    "repository_owner": (repo.get("owner") or {}).get("login"),
                    "secrets": secrets,
                    "hostnames": sorted(file_hosts)[:10],
                },
                source_module=self.name,
                confidence=0.9,
                depth=depth,
            )
            yield found
            yield Relation.create(
                entity.id, found.id, RelationType.EXPOSES if secrets else RelationType.ASSOCIATED_WITH,
                label="Secret in public code" if secrets else "Mentioned in public code",
            )  # fmt: skip
        entity.metadata["public_code"]["files_with_secrets"] = leaked

        for host in sorted(hosts - {domain})[:50]:
            sub = Entity.create(
                EntityType.SUBDOMAIN, host, label=host, metadata={"origin": "public code"},
                source_module=self.name, confidence=0.75, depth=depth,
            )  # fmt: skip
            yield sub
            yield Relation.create(sub.id, entity.id, RelationType.SUBDOMAIN_OF, label="Found in public code")
        for address in sorted(emails)[:25]:
            mail = Entity.create(
                EntityType.EMAIL, address, label=address, metadata={"origin": "public code"},
                source_module=self.name, confidence=0.8, depth=depth,
            )  # fmt: skip
            yield mail
            yield Relation.create(mail.id, entity.id, RelationType.ASSOCIATED_WITH, label="Found in public code")
