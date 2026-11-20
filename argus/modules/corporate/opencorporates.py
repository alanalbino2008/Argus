"""OpenCorporates: company registers of about 140 countries and US states, in one place.

For a company not already found in a national register Argus reads directly (UK, France,
Norway, Finland...), OpenCorporates gives its registration in whichever jurisdiction it is in:
number, status, incorporation and dissolution dates, type, address, former names and its
officers. For a person, it lists the companies where someone of that name is an officer.

Reached with the investigator's own OpenCorporates key (direct, no credits) or through Argus
Connect (credits). To keep a scan's cost predictable, it runs only on the scan's own target.
Officers found by name alone are marked as possible matches: names repeat.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, ClassVar

from argus.accounts.connect_client import available, lookup
from argus.accounts.connectors import ConnectError
from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.intel.names import similarity
from argus.modules.base import BaseModule
from argus.modules.corporate import company_name, person_name

MATCH = 0.92
OFFICERS = 35


def _company(c: dict[str, Any]) -> dict[str, Any]:
    jurisdiction = str(c.get("jurisdiction_code") or "")
    previous = [
        p.get("company_name") for p in c.get("previous_names") or [] if isinstance(p, dict) and p.get("company_name")
    ]
    meta = {
        "registry": f"OpenCorporates ({jurisdiction.upper().replace('_', '-')})" if jurisdiction else "OpenCorporates",
        "company_number": c.get("company_number"), "jurisdiction": jurisdiction, "legal_name": c.get("name"),
        "company_status": c.get("current_status") or ("dissolved" if c.get("dissolution_date") else None),
        "incorporated": c.get("incorporation_date"), "dissolved": c.get("dissolution_date"),
        "company_type": c.get("company_type"), "registered_address": c.get("registered_address_in_full"),
        "former_names": previous, "register_url": c.get("registry_url") or c.get("opencorporates_url"),
        "opencorporates_url": c.get("opencorporates_url"), "country": jurisdiction[:2].upper() or None,
    }  # fmt: skip
    return {k: v for k, v in meta.items() if v not in (None, "", [])}


class OpenCorporatesModule(BaseModule):
    name = "opencorporates"
    description = "OpenCorporates: company registers of ~140 countries and their officers (own key, or Argus credits)"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.ORGANIZATION, EntityType.PERSON]
    third_party_safe = True
    attack_techniques: ClassVar[tuple[str, ...]] = ("T1591.002", "T1589.003")

    @classmethod
    def is_configured(cls) -> bool:
        return available("opencorporates")

    def can_handle(self, entity: Entity) -> bool:
        if entity.depth != 0:
            return False  # the scan's own target only: every lookup costs credits
        if entity.type == EntityType.ORGANIZATION:
            return not entity.metadata.get("registry")  # already found in a national register
        return entity.type == EntityType.PERSON and len(entity.value.split()) >= 2

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        try:
            if entity.type == EntityType.ORGANIZATION:
                async for item in self._company(entity, session):
                    yield item
            else:
                async for item in self._officer(entity, session):
                    yield item
        except ConnectError as exc:
            self.report_error("opencorporates", exc.detail)

    async def _company(self, entity: Entity, session: HttpClient) -> AsyncIterator[Entity | Relation]:
        found = await lookup(session, "opencorporates", "search_companies", {"q": entity.value})
        rows = [r.get("company") or {} for r in (found.get("results") or {}).get("companies") or []]
        scored = sorted(((similarity(entity.value, r.get("name") or "", kind="company"), r) for r in rows),
                        key=lambda pair: (-pair[0], bool(pair[1].get("dissolution_date"))))  # fmt: skip
        good = [r for s, r in scored if s >= MATCH]
        if not good:
            if scored:
                entity.metadata["registry_candidates"] = [{"name": r.get("name"), "number": r.get("company_number"),
                                                           "jurisdiction": r.get("jurisdiction_code"), "score": s}
                                                          for s, r in scored[:5]]  # fmt: skip
            return
        if len({(r.get("jurisdiction_code"), r.get("company_number")) for r in good}) > 1:
            entity.metadata["same_name_elsewhere"] = [_company(r) for r in good[1:6]]  # tell the investigator
        best = good[0]
        detail = await lookup(session, "opencorporates", "company", {"jurisdiction": best.get("jurisdiction_code"),
                                                                      "number": best.get("company_number")})  # fmt: skip
        company = (detail.get("results") or {}).get("company") or best
        entity.metadata.update(_company(company))
        for row in (company.get("officers") or [])[:OFFICERS]:
            officer = row.get("officer") or {}
            raw = str(officer.get("name") or "")
            if not raw or officer.get("end_date"):
                continue  # current officers only
            corporate = raw.isupper() and any(
                w in raw.split() for w in ("LTD", "LIMITED", "LLC", "INC", "PLC", "SA", "AG", "GMBH")
            )
            name = company_name(raw) if corporate else person_name(raw)
            role = str(officer.get("position") or "officer")
            meta = {k: v for k, v in {"role": role, "appointed": officer.get("start_date"), "nationality":
                    officer.get("nationality"), "occupation": officer.get("occupation"),
                    "source_registry": entity.metadata.get("registry")}.items() if v}  # fmt: skip
            linked = Entity.create(EntityType.ORGANIZATION if corporate else EntityType.PERSON, name, label=name,
                                   metadata=meta, source_module=self.name, confidence=0.95, depth=entity.depth + 1)  # fmt: skip
            yield linked
            yield Relation.create(linked.id, entity.id, RelationType.OFFICER_OF, label=role)

    async def _officer(self, entity: Entity, session: HttpClient) -> AsyncIterator[Entity | Relation]:
        found = await lookup(session, "opencorporates", "search_officers", {"q": entity.value})
        count = 0
        for row in (found.get("results") or {}).get("officers") or []:
            officer = row.get("officer") or {}
            company = officer.get("company") or {}
            if similarity(entity.value, str(officer.get("name") or ""), kind="person") < MATCH or not company.get(
                "name"
            ):
                continue
            name = company_name(str(company["name"]))
            org = Entity.create(EntityType.ORGANIZATION, name, label=name, metadata=_company(company),
                                source_module=self.name, confidence=0.6, depth=entity.depth + 1)  # fmt: skip
            org.metadata["matched_person"] = {"name": person_name(str(officer.get("name"))),
                                              "how": "same name only: check it is the same person"}  # fmt: skip
            yield org
            yield Relation.create(entity.id, org.id, RelationType.OFFICER_OF, confidence=0.6,
                                  label=str(officer.get("position") or "officer") + ("" if not officer.get("end_date") else " (former)"))  # fmt: skip
            count += 1
        entity.metadata["opencorporates_officer_matches"] = count
