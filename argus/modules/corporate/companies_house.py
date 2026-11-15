"""UK Companies House: who runs a company, who really controls it, and their other companies.

For a **company** it finds the registered company, then:
* its details (number, status, incorporation date, registered office, business type);
* its **officers** (directors, secretaries), with roles and dates;
* its **persons with significant control**: the people or companies that own or control it,
  and how ("owns more than 75% of shares").

For a **director**, it lists their other appointments: every company they have run. Following a
director across companies is the core of company-network investigations: nominee directors, shell
companies and phoenix firms show up as one person sitting on dozens of boards.

For a **person** (a name typed in), it searches the register of officers. A matching name is
only a possibility (many people share names), so these are marked possible, with the date of
birth the register shows (month and year) to tell them apart.

Lookups use the investigator's own Companies House key when set, or Argus Connect (credits).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, ClassVar

from argus.accounts.connect_client import available, lookup
from argus.accounts.connectors import ConnectError
from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.core.settings import get_settings
from argus.intel.names import similarity
from argus.modules.base import BaseModule
from argus.modules.corporate import company_name, person_name

REGISTER = "https://find-and-update.company-information.service.gov.uk"
MATCH = 0.92


def _address(a: dict[str, Any] | None) -> str:
    a = a or {}
    parts = [
        a.get(k)
        for k in ("premises", "address_line_1", "address_line_2", "locality", "region", "postal_code", "country")
    ]
    return ", ".join(str(p) for p in parts if p)


def _dob(d: dict[str, Any] | None) -> str | None:
    return f"{d['year']}-{int(d['month']):02d}" if d and d.get("year") and d.get("month") else None


def _officer_id(item: dict[str, Any]) -> str | None:
    link = ((item.get("links") or {}).get("officer") or {}).get("appointments") or (item.get("links") or {}).get("self")
    parts = str(link or "").strip("/").split("/")
    return parts[1] if len(parts) >= 3 and parts[0] == "officers" else None


class CompaniesHouseModule(BaseModule):
    name = "companies_house"
    description = "UK Companies House: company details, directors, owners (PSC) and directors' other companies"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.ORGANIZATION, EntityType.PERSON]
    third_party_safe = True  # an official public register; never contacts the company
    attack_techniques = ("T1591.002", "T1589.003")  # business relationships; employee names

    @classmethod
    def is_configured(cls) -> bool:
        return available("companies_house")

    def can_handle(self, entity: Entity) -> bool:
        md = entity.metadata
        if entity.type == EntityType.ORGANIZATION:
            return entity.depth == 0 or bool(md.get("company_number") and md.get("registry") == "UK Companies House")
        return entity.depth == 0 or bool(md.get("ch_officer_id"))

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        try:
            if entity.type == EntityType.ORGANIZATION:
                async for item in self._company(entity, session):
                    yield item
            elif entity.metadata.get("ch_officer_id"):
                async for item in self._appointments(entity, entity.metadata["ch_officer_id"], session):
                    yield item
            else:
                async for item in self._find_person(entity, session):
                    yield item
        except ConnectError as exc:
            self.report_error("companies_house", exc.detail)

    # ------------------------------------------------------------------ companies
    async def _company(self, entity: Entity, session: HttpClient) -> AsyncIterator[Entity | Relation]:
        md = entity.metadata
        number = md.get("company_number")
        if not number:
            found = await lookup(session, "companies_house", "search_companies", {"q": entity.value})
            scored = sorted(((similarity(entity.value, i.get("title", ""), kind="company"), i) for i in found.get("items") or []),
                            key=lambda pair: -pair[0])  # fmt: skip
            if not scored or scored[0][0] < MATCH:
                if scored:
                    md["registry_candidates"] = [{"name": i.get("title"), "number": i.get("company_number"),
                                                  "status": i.get("company_status"), "score": s} for s, i in scored[:5]]  # fmt: skip
                return
            number = scored[0][1]["company_number"]
        company = await lookup(session, "companies_house", "company", {"number": number})
        if company.get("not_found"):
            return
        md.update(registry="UK Companies House", company_number=company.get("company_number", number),
                  legal_name=company.get("company_name"), company_status=company.get("company_status"),
                  incorporated=company.get("date_of_creation"), dissolved=company.get("date_of_cessation"),
                  company_type=company.get("type"), sic_codes=company.get("sic_codes") or [],
                  registered_address=_address(company.get("registered_office_address")),
                  register_url=f"{REGISTER}/company/{company.get('company_number', number)}")  # fmt: skip
        officers = await lookup(session, "companies_house", "officers", {"number": md["company_number"]})
        followed = 0
        limit = get_settings().companies_house_officer_limit
        for item in (officers.get("items") or [])[:35]:
            officer_id = _officer_id(item)
            is_company = (item.get("officer_role") or "").startswith("corporate")
            name = company_name(item.get("name", "")) if is_company else person_name(item.get("name", ""))
            if not name:
                continue
            active = not item.get("resigned_on")
            meta = {"source_registry": "UK Companies House", "role": item.get("officer_role"),
                    "appointed": item.get("appointed_on"), "resigned": item.get("resigned_on"),
                    "nationality": item.get("nationality"), "occupation": item.get("occupation"),
                    "born": _dob(item.get("date_of_birth")), "country_of_residence": item.get("country_of_residence")}  # fmt: skip
            if officer_id and active and followed < limit and not is_company:
                meta["ch_officer_id"] = officer_id
                meta["ch_company"] = md["company_number"]  # already linked: skipped among their other companies
                followed += 1
            person = Entity.create(EntityType.ORGANIZATION if is_company else EntityType.PERSON, name, label=name,
                                   metadata={k: v for k, v in meta.items() if v}, source_module=self.name,
                                   confidence=0.95, depth=entity.depth + 1)  # fmt: skip
            yield person
            yield Relation.create(person.id, entity.id, RelationType.OFFICER_OF,
                                  label=f"{(item.get('officer_role') or 'officer').replace('-', ' ')}"
                                        f"{'' if active else ' (resigned)'}",
                                  metadata={"role": item.get("officer_role"), "from": item.get("appointed_on"),
                                            "to": item.get("resigned_on")})  # fmt: skip
        psc = await lookup(session, "companies_house", "psc", {"number": md["company_number"]})
        for item in (psc.get("items") or [])[:25]:
            kind = item.get("kind", "")
            if "individual" in kind:
                etype, name = EntityType.PERSON, person_name(item.get("name", ""))
            elif "corporate" in kind or "legal-person" in kind:
                etype, name = EntityType.ORGANIZATION, company_name(item.get("name", ""))
            else:
                continue  # "super-secure" or a statement: nothing to name
            if not name:
                continue
            control = [n.replace("-", " ") for n in item.get("natures_of_control") or []]
            owner = Entity.create(etype, name, label=name, source_module=self.name, confidence=0.95,
                                  depth=entity.depth + 1,
                                  metadata={k: v for k, v in {"source_registry": "UK Companies House",
                                            "nationality": item.get("nationality"), "born": _dob(item.get("date_of_birth")),
                                            "country_of_residence": item.get("country_of_residence")}.items() if v})  # fmt: skip
            yield owner
            yield Relation.create(owner.id, entity.id, RelationType.CONTROLS,
                                  label="Significant control" + (" (ceased)" if item.get("ceased_on") else ""),
                                  metadata={"nature": control, "from": item.get("notified_on"),
                                            "to": item.get("ceased_on")})  # fmt: skip

    # ------------------------------------------------------------------ people
    async def _appointments(
        self, entity: Entity, officer_id: str, session: HttpClient
    ) -> AsyncIterator[Entity | Relation]:
        found = await lookup(session, "companies_house", "appointments", {"officer_id": officer_id})
        entity.metadata["appointments_total"] = found.get("total_results") or len(found.get("items") or [])
        for item in (found.get("items") or [])[:35]:
            to = item.get("appointed_to") or {}
            if not to.get("company_number") or not to.get("company_name"):
                continue
            if to["company_number"] == entity.metadata.get("ch_company"):
                continue  # the company this director was found through: already on the graph
            name = company_name(to["company_name"])
            company = Entity.create(EntityType.ORGANIZATION, name, label=name, source_module=self.name, confidence=0.95,
                                    depth=entity.depth + 1,
                                    metadata={"registry": "UK Companies House", "company_number": to["company_number"],
                                              "company_status": to.get("company_status"),
                                              "register_url": f"{REGISTER}/company/{to['company_number']}"})  # fmt: skip
            yield company
            yield Relation.create(entity.id, company.id, RelationType.OFFICER_OF,
                                  label=f"{(item.get('officer_role') or 'officer').replace('-', ' ')}"
                                        f"{' (resigned)' if item.get('resigned_on') else ''}",
                                  metadata={"role": item.get("officer_role"), "from": item.get("appointed_on"),
                                            "to": item.get("resigned_on")})  # fmt: skip

    async def _find_person(self, entity: Entity, session: HttpClient) -> AsyncIterator[Entity | Relation]:
        found = await lookup(session, "companies_house", "search_officers", {"q": entity.value})
        matches = []
        for item in (found.get("items") or [])[:10]:
            score = similarity(entity.value, item.get("title", ""), kind="person")
            if score >= MATCH and _officer_id(item):
                matches.append({"name": person_name(item.get("title", "")), "born": _dob(item.get("date_of_birth")),
                                "address": item.get("address_snippet"), "appointments": item.get("appointment_count"),
                                "officer_id": _officer_id(item), "score": score})  # fmt: skip
        entity.metadata["officer_matches"] = matches
        for match in matches[:3]:  # possibly the same person: follow each, clearly labelled
            async for item in self._appointments(entity, match["officer_id"], session):
                if isinstance(item, Entity):
                    item.confidence = 0.5
                    item.metadata["via_possible_match"] = f"{match['name']} (born {match['born'] or 'unknown'})"
                yield item
