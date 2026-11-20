"""The Gazette: the UK's official public record of insolvency notices.

Every UK company winding-up (voluntary or compulsory), administration, receivership, and every
personal bankruptcy and debt relief order is published in The Gazette. Argus searches its
insolvency notices for the exact name of the company or person, newest first, and records each
notice's type, date and link. Free, no key.

**Care with people.** A notice about a person is found by name, and names repeat: notices about
people are shown as possible matches to check against the notice itself (it usually gives an
address and date of birth). Deceased estates notices are never searched.
"""

from __future__ import annotations

import html
import re
from collections.abc import AsyncIterator
from typing import Any, ClassVar

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, ScanConfig
from argus.core.settings import get_settings
from argus.modules.base import BaseModule

LIMIT = 20
TAG = re.compile(r"<[^>]+>")
PERSONAL = ("bankruptcy", "debt relief", "individual voluntary", "bankrupt")


def _text(raw: Any) -> str:
    return " ".join(html.unescape(TAG.sub(" ", str(raw or ""))).split())[:300]


def _link(entry: dict[str, Any]) -> str:
    links = entry.get("link") or []
    links = links if isinstance(links, list) else [links]
    plain = next((link.get("@href") for link in links if isinstance(link, dict) and not link.get("@rel")
                  and "/notice/" in str(link.get("@href"))), None)  # fmt: skip
    return str(plain or entry.get("id") or "")


def notices(data: dict[str, Any]) -> list[dict[str, Any]]:
    entries = data.get("entry") or []
    entries = entries if isinstance(entries, list) else [entries]
    out = []
    for e in entries:
        category = e.get("category") or {}
        kind = str((category.get("@term") if isinstance(category, dict) else "") or e.get("title") or "Notice")
        summary = _text(e.get("content"))
        out.append({"type": kind, "about": str(e.get("title") or ""), "date": str(e.get("published") or "")[:10],
                    "url": _link(e), "summary": "" if summary.strip("… .") == "" else summary,
                    "code": e.get("f:notice-code"), "personal": any(word in kind.lower() for word in PERSONAL)})  # fmt: skip
    return out


class GazetteInsolvencyModule(BaseModule):
    name = "gazette_insolvency"
    description = (
        "The UK Gazette: insolvency notices (winding-up, administration, bankruptcy) for a company or person (free)"
    )
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.ORGANIZATION, EntityType.PERSON]
    third_party_safe = True  # an official public record; nobody is contacted
    attack_techniques: ClassVar[tuple[str, ...]] = ("T1591.002",)
    rate_limits: ClassVar[dict[str, float]] = {"www.thegazette.co.uk": 0.5}

    def can_handle(self, entity: Entity) -> bool:
        if not get_settings().gazette_url:
            return False
        if entity.type == EntityType.ORGANIZATION:
            country = str(entity.metadata.get("country") or "").upper()
            return entity.depth <= 1 and country in ("", "GB", "UK")
        return entity.depth == 0 and len(entity.value.split()) >= 2

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        base = get_settings().gazette_url.rstrip("/")
        name = entity.metadata.get("legal_name") or entity.value
        params = {"text": f'"{name}"', "results-page-size": str(LIMIT), "sort-by": "latest-date"}
        async with session.get(f"{base}/insolvency/notice/data.json", params=params) as resp:
            if resp.status != 200:
                return
            data = await resp.json(content_type=None)
        found = notices(data)
        if entity.type == EntityType.ORGANIZATION:
            found = [n for n in found if not n["personal"]]  # a company's notices, not its directors' bankruptcies
        if not found:
            entity.metadata["insolvency_notices_checked"] = True
            return
        entity.metadata["insolvency_notices"] = found
        entity.metadata["insolvency_notices_total"] = int(str(data.get("f:total") or len(found)) or 0)
        entity.metadata["insolvency_notice_match"] = (
            "exact name in the notice" if entity.type == EntityType.ORGANIZATION
            else "same name only: check the notice's address and date of birth")  # fmt: skip
        return
        yield  # an async generator that may yield nothing
