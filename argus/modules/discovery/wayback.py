"""Internet Archive (Wayback Machine): what the target's websites used to expose.

Organisations forget pages; the archive does not. One CDX query lists every URL ever
captured under a domain, which surfaces:

* forgotten sub-domains,
* sensitive files that were once public (``.env``, ``.git/``, database dumps, backups),
* admin and login panels, API descriptions (Swagger/OpenAPI, GraphQL),
* documents (PDF, Office) whose metadata names staff and software - see ``document_metadata``,
* URLs carrying credentials in their query string (values are redacted).

Passive: only archive.org is contacted, never the target. Archived does not mean
still live - findings say so, and active modules can confirm.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

CDX = (
    "https://web.archive.org/cdx/search/cdx?url={}&matchType=domain&output=json"
    "&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=25000"
)
MAX_PER_CATEGORY = 15
MAX_SUBDOMAINS = 300

SECRET_PARAMS = re.compile(
    r"(?i)^(access_?token|api_?key|apikey|auth|client_secret|key|passw(or)?d|pwd|secret|session(id)?|sig(nature)?|token)$"
)
CATEGORIES: list[tuple[str, re.Pattern[str]]] = [
    (
        "sensitive_file",
        re.compile(
            r"(?i)(/\.env(\.\w+)?$|/\.git(/|$)|/\.svn(/|$)|/\.DS_Store$|/\.htpasswd$|/id_[rd]sa$|/wp-config\.php\.\w+$"
            r"|/phpinfo\.php$|/server-status$|\.(sql|sql\.gz|bak|old|backup|swp|log|pem|key|ppk|kdbx|p12|pfx)$"
            r"|/(backup|dump|db|database)[^/]*\.(zip|tar|tgz|tar\.gz|gz|7z|rar)$)"
        ),
    ),
    (
        "admin_panel",
        re.compile(
            r"(?i)/(admin|administrator|wp-admin|wp-login\.php|phpmyadmin|pma|cpanel|webmail|jenkins|grafana|kibana"
            r"|manager/html|actuator|console|_admin|backend|cms)(/|$)"
        ),
    ),
    (
        "api",
        re.compile(r"(?i)(swagger(-ui)?(\.html|\.json|/)|openapi\.(json|ya?ml)$|/graphql$|/api-docs|\.wsdl$|/api/v\d)"),
    ),
    ("document", re.compile(r"(?i)\.(pdf|docx?|xlsx?|pptx?|odt|ods|odp|rtf)$")),
]


def redact_query(url: str) -> tuple[str, bool]:
    """Replace secret-looking query values with ``REDACTED``; returns (url, had_secret)."""
    parts = urlsplit(url)
    if not parts.query:
        return url, False
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    found = any(SECRET_PARAMS.match(k) and v for k, v in pairs)
    if not found:
        return url, False
    safe = [(k, "REDACTED" if SECRET_PARAMS.match(k) and v else v) for k, v in pairs]
    return urlunsplit(parts._replace(query=urlencode(safe))), True


def classify(url: str) -> str | None:
    path = urlsplit(url).path
    for name, pattern in CATEGORIES:
        if pattern.search(path):
            return name
    return None


def _iso(ts: str) -> str | None:
    return f"{ts[:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 and ts.isdigit() else None


class WaybackModule(BaseModule):
    name = "wayback"
    description = "Internet Archive: forgotten sub-domains, exposed files, admin panels, APIs and documents"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.DOMAIN]
    attack_techniques = ("T1593", "T1594")
    rate_limits: ClassVar[dict[str, float]] = {"web.archive.org": 1.0}

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth <= 1

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        domain = entity.value.strip().lower()
        async with session.get(CDX.format(quote(domain))) as resp:
            if resp.status != 200:
                self.report_error("wayback", f"HTTP {resp.status}")
                return
            rows = await resp.json(content_type=None)
        if not rows or len(rows) < 2:
            entity.metadata["wayback"] = {"urls_archived": 0}
            return

        subdomains: set[str] = set()
        buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
        first = min((r[1] for r in rows[1:] if len(r) > 1), default="")
        for row in rows[1:]:
            if len(row) < 4:
                continue
            original, ts, status, mime = row[:4]
            host = (urlsplit(original).hostname or "").lower().rstrip(".")
            if host.endswith("." + domain) and host != f"www.{domain}" and "*" not in host:
                subdomains.add(host)
            url, secret = redact_query(original)
            category = "credential_in_url" if secret else classify(original)
            if category:
                buckets[category].append({"url": url, "ts": ts, "status": status, "mime": mime})

        entity.metadata["wayback"] = {
            "urls_archived": len(rows) - 1,
            "first_archived": _iso(first),
            "subdomains": len(subdomains),
            "interesting": {k: len(v) for k, v in sorted(buckets.items())},
        }

        for host in sorted(subdomains)[:MAX_SUBDOMAINS]:
            sub = Entity.create(
                EntityType.SUBDOMAIN,
                host,
                label=host,
                metadata={"origin": "web archive"},
                source_module=self.name,
                confidence=0.7,
                depth=entity.depth + 1,
            )
            yield sub
            yield Relation.create(sub.id, entity.id, RelationType.SUBDOMAIN_OF, label="Archived sub-domain")

        for category, items in sorted(buckets.items()):
            # Prefer captures that returned 200 and the most recent ones.
            items.sort(key=lambda i: (i["status"] != "200", -int(i["ts"] or 0)))
            for item in items[:MAX_PER_CATEGORY]:
                parts = urlsplit(item["url"])
                found = Entity.create(
                    EntityType.URL,
                    item["url"],
                    label=f"{parts.hostname}{parts.path}"[:90],
                    metadata={
                        "category": category,
                        "origin": "web archive",
                        "archived_on": _iso(item["ts"]),
                        "archived_status": item["status"],
                        "mime": item["mime"],
                        "archive_url": f"https://web.archive.org/web/{item['ts']}/{item['url']}",
                        "live": "unverified",
                    },
                    source_module=self.name,
                    confidence=0.9,
                    depth=entity.depth + 1,
                )
                yield found
                rel = (
                    RelationType.EXPOSES
                    if category in ("sensitive_file", "credential_in_url")
                    else RelationType.ASSOCIATED_WITH
                )
                yield Relation.create(entity.id, found.id, rel, label="Archived " + category.replace("_", " "))
