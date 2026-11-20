"""US federal court records, from CourtListener (the Free Law Project).

CourtListener holds the dockets of US federal courts (from PACER, through the RECAP archive) and
millions of court opinions. Argus searches for cases where the company or person is named and
records each case's name, court, filing date, docket number, nature of suit and link.

Reached with the investigator's own CourtListener key (free account; direct, no credits) or
through Argus Connect (credits). Runs on the scan's own target only. A person's name can belong
to many people: cases are possible matches until checked.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, ClassVar

from argus.accounts.connect_client import available, lookup
from argus.accounts.connectors import ConnectError
from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, ScanConfig
from argus.intel.names import similarity
from argus.modules.base import BaseModule

SITE = "https://www.courtlistener.com"
LIMIT = 20
MATCH = 0.9


def case(row: dict[str, Any], kind: str) -> dict[str, Any]:
    url = row.get("docket_absolute_url") or row.get("absolute_url") or ""
    meta = {"name": row.get("caseName") or row.get("case_name"), "court": row.get("court") or row.get("court_id"),
            "filed": row.get("dateFiled"), "terminated": row.get("dateTerminated"),
            "docket": row.get("docketNumber"), "nature": row.get("suitNature") or row.get("cause"),
            "kind": kind, "url": f"{SITE}{url}" if url.startswith("/") else url or None}  # fmt: skip
    return {k: v for k, v in meta.items() if v}


def named(target: str, row: dict[str, Any], kind: str) -> bool:
    """Is the target one of the case's parties (or, without a party list, in its name)?"""
    parties = row.get("party") or []
    if isinstance(parties, list) and parties:
        return any(similarity(target, str(p), kind=kind) >= MATCH for p in parties)
    return target.lower() in str(row.get("caseName") or row.get("case_name") or "").lower()


class CourtRecordsModule(BaseModule):
    name = "court_records"
    description = "US federal court cases naming a company or person, from CourtListener (own key, or Argus credits)"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.ORGANIZATION, EntityType.PERSON]
    third_party_safe = True
    attack_techniques: ClassVar[tuple[str, ...]] = ("T1591.002",)

    @classmethod
    def is_configured(cls) -> bool:
        return available("courtlistener")

    def can_handle(self, entity: Entity) -> bool:
        if entity.depth != 0:
            return False  # the scan's own target only: every search costs credits
        return entity.type == EntityType.ORGANIZATION or len(entity.value.split()) >= 2

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        kind = "company" if entity.type == EntityType.ORGANIZATION else "person"
        name = entity.metadata.get("legal_name") or entity.value
        try:
            data = await lookup(session, "courtlistener", "dockets", {"q": f'"{name}"'})
        except ConnectError as exc:
            self.report_error("courtlistener", exc.detail)
            return
        rows = data.get("results") or []
        cases = [case(r, "docket") for r in rows if named(name, r, kind)][:LIMIT]
        entity.metadata["court_cases"] = cases
        entity.metadata["court_cases_total"] = data.get("count") if isinstance(data.get("count"), int) else len(cases)
        if cases and kind == "person":
            entity.metadata["court_case_match"] = "same name only: check the case is about this person"
        return
        yield  # an async generator that may yield nothing
