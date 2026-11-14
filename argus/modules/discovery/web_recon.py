"""What the target's own website reveals: contacts, policies and accidentally exposed files.

Active (contacts the target), so it is skipped by passive-only scans. Per host:

* ``security.txt`` (RFC 9116): security contacts and whether the file has expired;
* ``robots.txt``: paths the owner asked search engines to avoid - often the interesting ones;
* exposed files, each confirmed by its *content* rather than the status code (so
  "soft-404" sites that answer 200 to everything cause no false positives):
  ``.git/HEAD``, ``.env``, ``.DS_Store``, Apache ``server-status``, ``phpinfo``,
  Spring Boot ``/actuator/env``. From ``.env`` only variable *names* are kept;
* contact details published on the home, contact and about pages: email addresses on
  the target's own domain and phone numbers (``tel:`` links, or international format).
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Callable
from typing import Any, ClassVar

import aiohttp

from argus.core.http import HttpClient, read_limited
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

MAX_PAGE = 600_000
INTERESTING_ROBOTS = re.compile(
    r"(?i)(admin|backup|private|internal|staging|dev|test|old|tmp|config|secret|api|login|dashboard|upload)"
)
ENV_VAR = re.compile(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]{1,60})\s*=")
TEL_LINK = re.compile(r"""href=["']tel:([+\d][\d\s().%20-]{6,24})["']""", re.I)
INTL_PHONE = re.compile(r"(?<![\w+])\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}(?!\d)")


def _env_names(body: bytes) -> list[str] | None:
    text = body.decode("utf-8", errors="ignore")
    if "<html" in text.lower():
        return None
    names = ENV_VAR.findall(text)
    return sorted(set(names))[:30] if len(names) >= 2 else None


# path -> (label, impact, check returning evidence or None)
EXPOSED_FILES: dict[str, tuple[str, Callable[[bytes], Any]]] = {
    "/.git/HEAD": ("Git repository metadata", lambda b: "ref: refs/" if b.startswith(b"ref: refs/") else None),
    "/.env": ("Environment file with configuration secrets", _env_names),
    "/.DS_Store": ("macOS folder index (lists file names)", lambda b: "Bud1" if b[4:8] == b"Bud1" else None),
    "/server-status": (
        "Apache server-status page",
        lambda b: "Apache Server Status" if b"Apache Server Status" in b else None,
    ),
    "/phpinfo.php": (
        "phpinfo() page",
        lambda b: "PHP configuration" if b"phpinfo()" in b and b"PHP Version" in b else None,
    ),
    "/actuator/env": (
        "Spring Boot actuator environment",
        lambda b: "propertySources" if b'"propertySources"' in b else None,
    ),
}


def normalise_phone(raw: str) -> str | None:
    """E.164-style ``+441234567890``; None unless it has a country code and 8-15 digits."""
    raw = raw.replace("%20", " ").replace("(0)", "").strip()  # "+44 (0)20": the trunk 0 is not dialled
    digits = re.sub(r"\D", "", raw)
    if not raw.startswith("+") or not 8 <= len(digits) <= 15:
        return None
    return "+" + digits


def extract_contacts(html: str, domain: str) -> tuple[set[str], dict[str, float]]:
    emails = {
        m.group(0).lower()
        for m in re.finditer(r"\b[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)*" + re.escape(domain) + r")\b", html, re.I)
    }
    phones: dict[str, float] = {}
    for raw in TEL_LINK.findall(html):
        number = normalise_phone(raw)
        if number:
            phones[number] = 0.8  # deliberately published as a clickable number
    text = re.sub(r"<[^>]+>", " ", html)
    for raw in INTL_PHONE.findall(text):
        number = normalise_phone(raw)
        if number:
            phones.setdefault(number, 0.55)
    return emails, phones


def parse_security_txt(text: str) -> dict[str, Any]:
    fields: dict[str, list[str]] = {}
    for line in text.splitlines():
        if ":" in line and not line.lstrip().startswith("#"):
            key, _, value = line.partition(":")
            fields.setdefault(key.strip().lower(), []).append(value.strip())
    return {
        "contacts": fields.get("contact", [])[:5],
        "expires": next(iter(fields.get("expires", [])), None),
        "policy": next(iter(fields.get("policy", [])), None),
    }


class WebReconModule(BaseModule):
    name = "web_recon"
    description = "Website exposure: security.txt, robots.txt, exposed files (.git, .env…), published contacts"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.DOMAIN, EntityType.SUBDOMAIN]
    attack_techniques = ("T1594", "T1595.003")
    active = True

    def can_handle(self, entity: Entity) -> bool:
        return super().can_handle(entity) and entity.depth <= 1

    async def _get(self, session: HttpClient, url: str, config: ScanConfig) -> tuple[int, bytes]:
        timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
        async with session.get(url, timeout=timeout, allow_redirects=False) as resp:
            if resp.status != 200:
                return resp.status, b""
            return 200, (await read_limited(resp, MAX_PAGE)) or b""

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        host = entity.value.strip().lower()
        base = f"https://{host}"
        domain = host.removeprefix("www.")
        depth = entity.depth + 1

        def url_entity(path: str, category: str, confidence: float, **md: Any) -> Entity:
            return Entity.create(
                EntityType.URL, base + path, label=host + path,
                metadata={"category": category, "origin": "live website", "live": "confirmed", **md},
                source_module=self.name, confidence=confidence, depth=depth,
            )  # fmt: skip

        # 1. security.txt
        status, body = await self._get(session, f"{base}/.well-known/security.txt", config)
        if status != 200 or b"contact:" not in body.lower():
            status, body = await self._get(session, f"{base}/security.txt", config)
        if status == 200 and b"contact:" in body.lower():
            info = parse_security_txt(body.decode("utf-8", errors="ignore"))
            entity.metadata["security_txt"] = {"present": True, **info}
            for contact in info["contacts"]:
                if contact.lower().startswith("mailto:"):
                    address = contact[7:].strip().lower()
                    mail = Entity.create(
                        EntityType.EMAIL, address, label=address, metadata={"origin": "security.txt", "role_mailbox": True},
                        source_module=self.name, confidence=0.95, depth=depth,
                    )  # fmt: skip
                    yield mail
                    yield Relation.create(entity.id, mail.id, RelationType.ASSOCIATED_WITH, label="Security contact")
        else:
            entity.metadata["security_txt"] = {"present": False}

        # 2. robots.txt
        status, body = await self._get(session, f"{base}/robots.txt", config)
        if status == 200 and b"<html" not in body[:500].lower():
            disallowed = re.findall(r"(?im)^\s*disallow:\s*(/\S*)", body.decode("utf-8", errors="ignore"))
            entity.metadata["robots_disallow"] = len(disallowed)
            for path in sorted({p for p in disallowed if INTERESTING_ROBOTS.search(p) and "*" not in p})[:10]:
                found = url_entity(path, "robots", 0.8, note="Listed as Disallow in robots.txt")
                found.metadata["live"] = "unverified"
                yield found
                yield Relation.create(
                    entity.id, found.id, RelationType.ASSOCIATED_WITH, label="Hidden from search engines"
                )

        # 3. exposed files, confirmed by content
        exposed = []
        for path, (label, check) in EXPOSED_FILES.items():
            status, body = await self._get(session, base + path, config)
            evidence = check(body) if status == 200 and body else None
            if not evidence:
                continue
            exposed.append(path)
            found = url_entity(
                path, "exposed_file", 0.95, file=label,
                evidence=evidence if isinstance(evidence, str) else f"variables: {', '.join(evidence)}",
            )  # fmt: skip
            yield found
            yield Relation.create(entity.id, found.id, RelationType.EXPOSES, label=f"Exposes {label}")
        entity.metadata["exposed_files"] = exposed

        # 4. contacts published on the site
        emails: set[str] = set()
        phones: dict[str, float] = {}
        for path in ("/", "/contact", "/contact-us", "/about"):
            status, body = await self._get(session, base + path, config)
            if status == 200:
                found_emails, found_phones = extract_contacts(body.decode("utf-8", errors="ignore"), domain)
                emails |= found_emails
                for number, confidence in found_phones.items():
                    phones[number] = max(confidence, phones.get(number, 0))
        for address in sorted(emails)[:20]:
            mail = Entity.create(
                EntityType.EMAIL, address, label=address, metadata={"origin": "published on website"},
                source_module=self.name, confidence=0.9, depth=depth,
            )  # fmt: skip
            yield mail
            yield Relation.create(mail.id, entity.id, RelationType.ASSOCIATED_WITH, label="Published on website")
        for number, confidence in sorted(phones.items())[:10]:
            phone = Entity.create(
                EntityType.PHONE, number, label=number, metadata={"origin": "published on website"},
                source_module=self.name, confidence=confidence, depth=depth,
            )  # fmt: skip
            yield phone
            yield Relation.create(phone.id, entity.id, RelationType.ASSOCIATED_WITH, label="Published on website")
