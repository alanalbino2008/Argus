"""Free company registers and public records: GLEIF (who owns whom), the SEC, and the Offshore Leaks.

**GLEIF**, the Global Legal Entity Identifier Foundation, keeps the LEI register: every company
that trades financial instruments anywhere has a 20-character LEI. It records the legal name,
registered and head-office addresses, jurisdiction and status, and **ownership**: the direct
parent and the ultimate parent. Free, no key.

**SEC EDGAR**: US-listed companies, with their filing identifier (CIK), state of incorporation,
business type, addresses, former names and recent filings. Free, no key; the SEC asks every
caller to identify itself with an organisation name and contact email
(``ARGUS_SEC_USER_AGENT``).

**ICIJ Offshore Leaks**: the International Consortium of Investigative Journalists' database of
offshore companies and the people behind them, from the Panama, Paradise and Pandora Papers and
other leaks. Free; licensed under the Open Database Licence, so results credit ICIJ. Appearing in
it is not evidence of wrongdoing: many offshore structures are legal.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import AsyncIterator
from typing import Any, ClassVar
from urllib.parse import quote

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.core.settings import get_settings
from argus.intel import watchlists
from argus.intel.names import similarity
from argus.modules.base import BaseModule
from argus.modules.corporate import company_name

MATCH = 0.92


# ---------------------------------------------------------------------------- GLEIF
def _lei_record(data: dict[str, Any]) -> dict[str, Any]:
    attrs = data.get("attributes") or {}
    entity = attrs.get("entity") or {}

    def address(a: dict[str, Any] | None) -> str:
        a = a or {}
        return ", ".join(
            str(p) for p in [*(a.get("addressLines") or []), a.get("city"), a.get("postalCode"), a.get("country")] if p
        )

    return {k: v for k, v in {
        "lei": attrs.get("lei") or data.get("id"), "legal_name": (entity.get("legalName") or {}).get("name"),
        "jurisdiction": entity.get("jurisdiction"), "entity_status": entity.get("status"),
        "registered_address": address(entity.get("legalAddress")), "head_office": address(entity.get("headquartersAddress")),
        "registered_as": entity.get("registeredAs"), "lei_status": (attrs.get("registration") or {}).get("status"),
    }.items() if v}  # fmt: skip


class GleifModule(BaseModule):
    name = "gleif"
    description = "Global LEI register: legal name, addresses, jurisdiction and parent companies (free)"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.ORGANIZATION]
    third_party_safe = True
    attack_techniques = ("T1591.002",)  # business relationships

    def can_handle(self, entity: Entity) -> bool:
        return entity.type == EntityType.ORGANIZATION and entity.depth <= 1 and bool(get_settings().gleif_url)

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        base = get_settings().gleif_url.rstrip("/")
        async with session.get(f"{base}/lei-records", params={"filter[fulltext]": entity.value, "page[size]": "5"},
                               headers={"Accept": "application/vnd.api+json"}) as resp:  # fmt: skip
            if resp.status != 200:
                return
            records = (await resp.json(content_type=None)).get("data") or []
        best = max(((similarity(entity.value, _lei_record(r).get("legal_name", ""), kind="company"), r) for r in records),
                   key=lambda pair: pair[0], default=(0.0, None))  # fmt: skip
        if best[1] is None or best[0] < MATCH:
            return
        record = _lei_record(best[1])
        entity.metadata.update({**record, "lei_url": f"https://search.gleif.org/#/record/{record['lei']}"})
        for relation in ("direct-parent", "ultimate-parent"):
            async with session.get(f"{base}/lei-records/{record['lei']}/{relation}",
                                   headers={"Accept": "application/vnd.api+json"}) as resp:  # fmt: skip
                if resp.status != 200:
                    continue
                parent = _lei_record((await resp.json(content_type=None)).get("data") or {})
            if not parent.get("legal_name") or parent.get("lei") == record["lei"]:
                continue
            name = company_name(parent["legal_name"])
            org = Entity.create(EntityType.ORGANIZATION, name, label=name, metadata=parent, source_module=self.name,
                                confidence=0.95, depth=entity.depth + 1)  # fmt: skip
            yield org
            yield Relation.create(entity.id, org.id, RelationType.SUBSIDIARY_OF,
                                  label="Direct parent" if relation == "direct-parent" else "Ultimate parent")  # fmt: skip


# ---------------------------------------------------------------------------- SEC EDGAR
_tickers: dict[str, Any] = {"loaded": 0.0, "rows": []}


class SecEdgarModule(BaseModule):
    name = "sec_edgar"
    description = "SEC EDGAR: US-listed companies' filing ID, incorporation, addresses, former names, filings (free)"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.ORGANIZATION]
    requires_settings = ("sec_user_agent",)
    third_party_safe = True
    attack_techniques = ("T1591",)

    def can_handle(self, entity: Entity) -> bool:
        return entity.type == EntityType.ORGANIZATION and entity.depth <= 1

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        headers = {"User-Agent": get_settings().sec_user_agent, "Accept": "application/json"}
        if time.monotonic() - _tickers["loaded"] > 86400 or not _tickers["rows"]:
            async with session.get("https://www.sec.gov/files/company_tickers.json", headers=headers) as resp:
                if resp.status != 200:
                    return
                data = await resp.json(content_type=None)
            _tickers["rows"] = [
                (str(v.get("title", "")), int(v.get("cik_str", 0)), v.get("ticker")) for v in data.values()
            ]
            _tickers["loaded"] = time.monotonic()
        best = max(((similarity(entity.value, title, kind="company"), cik, ticker) for title, cik, ticker in _tickers["rows"]),
                   key=lambda row: row[0], default=(0.0, 0, None))  # fmt: skip
        if best[0] < MATCH:
            return
        cik = f"{best[1]:010d}"
        async with session.get(f"https://data.sec.gov/submissions/CIK{cik}.json", headers=headers) as resp:
            if resp.status != 200:
                return
            sub = await resp.json(content_type=None)
        recent = (sub.get("filings") or {}).get("recent") or {}
        filings = [
            {"form": f, "date": d}
            for f, d in zip(recent.get("form") or [], recent.get("filingDate") or [], strict=False)
        ][:10]
        business = (sub.get("addresses") or {}).get("business") or {}
        entity.metadata.update({k: v for k, v in {
            "sec_cik": cik, "ticker": best[2], "sec_name": sub.get("name"), "sic": sub.get("sicDescription"),
            "state_of_incorporation": sub.get("stateOfIncorporation"),
            "business_address": ", ".join(str(business.get(k)) for k in ("street1", "city", "stateOrCountry", "zipCode")
                                          if business.get(k)),
            "former_names": [n.get("name") for n in sub.get("formerNames") or [] if n.get("name")],
            "recent_filings": filings, "sec_url": f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}",
        }.items() if v})  # fmt: skip
        return
        yield  # pragma: no cover - this module only enriches the company


# ---------------------------------------------------------------------------- ICIJ Offshore Leaks
class OffshoreLeaksModule(BaseModule):
    name = "offshore_leaks"
    description = "ICIJ Offshore Leaks Database (Panama, Paradise, Pandora Papers...): people and companies named"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.PERSON, EntityType.ORGANIZATION]
    third_party_safe = True
    attack_techniques = ("T1593",)

    def can_handle(self, entity: Entity) -> bool:
        return (
            entity.type in self.supported_entity_types and entity.depth <= 1 and bool(get_settings().offshore_leaks_url)
        )

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        base = get_settings().offshore_leaks_url.rstrip("/")
        person = entity.type == EntityType.PERSON
        queries = {"q0": {"query": entity.value, "type": "Officer" if person else "Entity", "limit": 5}}
        async with session.get(f"{base}/api/v1/reconcile", params={"queries": json.dumps(queries)}) as resp:
            if resp.status != 200:
                return
            results = ((await resp.json(content_type=None)).get("q0") or {}).get("result") or []
        hits = []
        for r in results:
            score = similarity(entity.value, str(r.get("name", "")), kind="person" if person else "company")
            if score >= MATCH and r.get("id"):
                hits.append({"name": r.get("name"), "score": score, "id": str(r["id"]),
                             "url": f"{base}/nodes/{quote(str(r['id']), safe='')}"})  # fmt: skip
        if hits:
            entity.metadata["offshore_leaks"] = hits[:5]
            entity.metadata["offshore_leaks_credit"] = "ICIJ Offshore Leaks Database (ODbL)"
        return
        yield  # pragma: no cover - this module only enriches


# ---------------------------------------------------------------------------- sanctions by name
def differences(known: dict[str, Any], listed: dict[str, str]) -> list[str]:
    """What we know about someone that contradicts a listing: a different birth year or nationality."""
    out = []
    born = re.search(r"\b(19|20)\d{2}\b", str(known.get("born") or ""))
    listed_years = set(re.findall(r"\b(?:19|20)\d{2}\b", listed.get("Date of birth", "")))
    if born and listed_years and born.group(0) not in listed_years:
        out.append(f"Born {born.group(0)}, but the listed person was born {', '.join(sorted(listed_years))}")
    nationality = str(known.get("nationality") or "").strip().lower()
    listed_nat = listed.get("Nationality", "").lower()
    if nationality and listed_nat and nationality[:4] not in listed_nat and listed_nat[:4] not in nationality:
        out.append(f"Nationality {known['nationality']}, but the listed person's is {listed['Nationality']}")
    return out


class SanctionsScreenModule(BaseModule):
    name = "sanctions_screen"
    description = "Screens people and companies against the US (OFAC), UK and UN sanctions lists by name"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.PERSON, EntityType.ORGANIZATION]
    third_party_safe = True
    attack_techniques = ("T1593",)
    enrichment = True

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        await watchlists.load(session)
        kind = "person" if entity.type == EntityType.PERSON else "company"
        matches = watchlists.screen(entity.value, kind=kind)
        for match in matches:
            conflicts = differences(entity.metadata, match.get("details") or {})
            if conflicts:
                match["conflicts"] = conflicts  # details that point to a different person
        if matches:
            entity.metadata["sanction_matches"] = matches
        return
        yield  # pragma: no cover - this module only enriches
