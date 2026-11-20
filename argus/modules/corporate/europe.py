"""European company registers, free and open: France, Norway and Finland.

**France** (``recherche-entreprises.api.gouv.fr``, the State's company search, from INSEE's SIRENE
and the national company register): every French company, its SIREN number, status, legal form,
activity, head office, and its **directors and partners** (name, role, month and year of birth).
It can also be searched by a **person**, which finds every French company they direct. Free, no
key.

**Norway** (``data.brreg.no``, the Brønnøysund Register Centre): every Norwegian organisation,
with founding date, legal form, industry, employees, address, website, **bankruptcy and
winding-up flags**, and its **roles**: managing director, board chair and members, auditor and
accountant. Free, no key.

**Finland** (``avoindata.prh.fi``, the Finnish Patent and Registration Office): every Finnish
company, its business ID, names (current and former), legal form, line of business, address,
website and status, including bankruptcy or liquidation. Finland's open data has no directors.
Free, no key.

**Privacy.** Registers publish directors' dates of birth. Like the UK register, Argus keeps only
the month and year, and leaves out people the register marks as deceased.

**Matching.** A company is only taken as the target when its registered name matches closely.
People found by name alone, in France's person search, are marked as possible matches unless
their month of birth agrees too.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, ClassVar

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.core.settings import get_settings
from argus.intel.names import similarity
from argus.modules.base import BaseModule
from argus.modules.corporate import company_name, person_name

MATCH = 0.92
PEOPLE_LIMIT = 35


def _born(value: Any) -> str | None:
    """Month and year only ("1964-12"), whatever the register publishes."""
    text = str(value or "").strip()
    return text[:7] if len(text) >= 7 and text[4] == "-" else (text[:4] if len(text) == 4 else None)


def _clean(meta: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in meta.items() if v not in (None, "", [], {})}


def _best(target: str, rows: list[tuple[str, Any]]) -> tuple[float, Any]:
    scored = [(similarity(target, name, kind="company"), row) for name, row in rows if name]
    return max(scored, key=lambda pair: pair[0], default=(0.0, None))


class _RegisterModule(BaseModule):
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.ORGANIZATION]
    third_party_safe = True  # official public registers; the company itself is never contacted
    attack_techniques: ClassVar[tuple[str, ...]] = ("T1591.002", "T1589.003")  # business relationships; staff
    registry = ""
    url_setting = ""

    def base(self) -> str:
        return str(getattr(get_settings(), self.url_setting, "") or "").rstrip("/")

    def can_handle(self, entity: Entity) -> bool:
        md = entity.metadata
        if entity.type != EntityType.ORGANIZATION or not self.base():
            return False
        if md.get("registry") and md.get("registry") != self.registry:
            return False  # already identified in another country's register
        return entity.depth <= 1

    def _person(self, entity: Entity, name: str, meta: dict[str, Any], role: str) -> tuple[Entity, Relation]:
        person = Entity.create(EntityType.PERSON, name, label=name, metadata=_clean({"source_registry": self.registry, **meta}),
                               source_module=self.name, confidence=0.95, depth=entity.depth + 1)  # fmt: skip
        return person, Relation.create(person.id, entity.id, RelationType.OFFICER_OF, label=role)

    def _organisation(self, entity: Entity, name: str, meta: dict[str, Any], role: str) -> tuple[Entity, Relation]:
        org = Entity.create(EntityType.ORGANIZATION, name, label=name, metadata=_clean({"source_registry": self.registry, **meta}),
                            source_module=self.name, confidence=0.95, depth=entity.depth + 1)  # fmt: skip
        return org, Relation.create(org.id, entity.id, RelationType.OFFICER_OF, label=role)


# ---------------------------------------------------------------------------- France
FR_STATUS = {"A": "active", "C": "ceased"}
FR_ROLES = {  # the register's French titles, in English (the French kept alongside)
    "président": "president", "directeur général": "chief executive", "directeur général délégué": "deputy chief executive",
    "administrateur": "board member", "président du conseil d'administration": "chair of the board",
    "gérant": "manager", "co-gérant": "co-manager", "associé": "partner", "associé indéfiniment responsable":
    "partner (unlimited liability)", "gérant et associé indéfiniment responsable": "manager and partner (unlimited liability)",
    "commissaire aux comptes titulaire": "statutory auditor", "commissaire aux comptes suppléant": "alternate auditor",
    "membre du conseil de surveillance": "supervisory board member", "président du conseil de surveillance":
    "chair of the supervisory board", "membre du directoire": "management board member", "président du directoire":
    "chair of the management board", "liquidateur": "liquidator", "directeur": "director",
}  # fmt: skip


def _fr_role(raw: Any) -> str:
    text = " ".join(str(raw or "director").split())
    english = FR_ROLES.get(text.lower())
    return f"{english} ({text})" if english else text


def _fr_company(row: dict[str, Any]) -> dict[str, Any]:
    head = row.get("siege") or {}
    siren = row.get("siren")
    return _clean({
        "registry": "France (SIRENE / RNE)", "company_number": siren, "legal_name": row.get("nom_raison_sociale")
        or row.get("nom_complet"), "company_status": FR_STATUS.get(row.get("etat_administratif") or ""),
        "incorporated": row.get("date_creation"), "dissolved": row.get("date_fermeture"),
        "legal_form_code": row.get("nature_juridique"), "activity_code": row.get("activite_principale"),
        "company_size": row.get("categorie_entreprise"), "establishments": row.get("nombre_etablissements"),
        "registered_address": head.get("adresse"), "country": "FR",
        "register_url": f"https://annuaire-entreprises.data.gouv.fr/entreprise/{siren}" if siren else None,
    })  # fmt: skip


def _fr_name(d: dict[str, Any]) -> str:
    given = str(d.get("prenoms") or "").split(" ")[0]  # the first given name: registers list them all
    return person_name(f"{d.get('nom') or ''}, {given}") if d.get("nom") else ""


class FranceRegistryModule(_RegisterModule):
    name = "france_registry"
    description = (
        "France's company register: company details, directors and partners; a person's French directorships (free)"
    )
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.ORGANIZATION, EntityType.PERSON]
    registry = "France (SIRENE / RNE)"
    url_setting = "france_registry_url"
    rate_limits: ClassVar[dict[str, float]] = {"recherche-entreprises.api.gouv.fr": 0.15}  # 7 requests a second

    def can_handle(self, entity: Entity) -> bool:
        if entity.type == EntityType.PERSON:
            return bool(self.base()) and entity.depth == 0 and len(entity.value.split()) >= 2
        return super().can_handle(entity)

    async def _search(self, session: HttpClient, params: dict[str, str]) -> list[dict[str, Any]]:
        async with session.get(f"{self.base()}/search", params={**params, "per_page": "10"}) as resp:
            if resp.status != 200:
                return []
            return (await resp.json(content_type=None)).get("results") or []

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        if entity.type == EntityType.PERSON:
            async for item in self._directorships(entity, session):
                yield item
            return
        number = entity.metadata.get("company_number") if entity.metadata.get("registry") == self.registry else None
        rows = await self._search(session, {"q": number or entity.value})
        score, row = _best(entity.value, [(r.get("nom_complet") or "", r) for r in rows])
        if number:
            row = next((r for r in rows if r.get("siren") == number), row)
        elif row is None or score < MATCH:
            return
        entity.metadata.update(_fr_company(row))
        for d in (row.get("dirigeants") or [])[:PEOPLE_LIMIT]:
            role = _fr_role(d.get("qualite"))
            if d.get("type_dirigeant") == "personne morale" or d.get("denomination"):
                name = company_name(str(d.get("denomination") or ""))
                if name:
                    for item in self._organisation(entity, name, {"company_number": d.get("siren"), "role": role,
                                                                 "country": "FR"}, role):  # fmt: skip
                        yield item
                continue
            name = _fr_name(d)
            if name:
                for item in self._person(entity, name, {"role": role, "born": _born(d.get("date_de_naissance")),
                                                       "nationality": d.get("nationalite")}, role):  # fmt: skip
                    yield item

    async def _directorships(self, entity: Entity, session: HttpClient) -> AsyncIterator[Entity | Relation]:
        """Every French company where someone of this name is a director or partner."""
        given, _, surname = entity.value.strip().partition(" ")
        rows = await self._search(session, {"nom_personne": surname, "prenoms_personne": given,
                                            "type_personne": "dirigeant"})  # fmt: skip
        born = str(entity.metadata.get("born") or "")[:7]
        found = 0
        for row in rows:
            match = next((d for d in row.get("dirigeants") or [] if d.get("nom") and
                          similarity(surname, str(d.get("nom")), kind="person") >= MATCH and
                          given.lower() in str(d.get("prenoms") or "").lower().split()), None)  # fmt: skip
            if match is None:
                continue
            same_birth = bool(born) and _born(match.get("date_de_naissance")) == born
            name = company_name(row.get("nom_complet") or "")
            company = Entity.create(EntityType.ORGANIZATION, name, label=name, metadata=_fr_company(row),
                                    source_module=self.name, confidence=0.9 if same_birth else 0.6,
                                    depth=entity.depth + 1)  # fmt: skip
            company.metadata["matched_person"] = _clean({
                "name": _fr_name(match), "born": _born(match.get("date_de_naissance")),
                "how": "same name and month of birth" if same_birth else "same name only: check it is the same person",
            })  # fmt: skip
            yield company
            yield Relation.create(entity.id, company.id, RelationType.OFFICER_OF, label=_fr_role(match.get("qualite")),
                                  confidence=0.9 if same_birth else 0.6)  # fmt: skip
            found += 1
        entity.metadata["french_directorships"] = found


# ---------------------------------------------------------------------------- Norway
NO_ROLES = {"DAGL": "managing director", "LEDE": "chair of the board", "NEST": "deputy chair", "MEDL": "board member",
            "VARA": "deputy board member", "REVI": "auditor", "REGN": "accountant", "KONT": "contact person",
            "INNH": "owner", "DTPR": "partner (jointly liable)", "DTSO": "partner (severally liable)",
            "KOMP": "general partner", "OBS": "observer", "FFØR": "business manager"}  # fmt: skip


def _no_address(addr: dict[str, Any] | None) -> str | None:
    if not addr:
        return None
    parts = [*(addr.get("adresse") or []), f"{addr.get('postnummer') or ''} {addr.get('poststed') or ''}".strip(),
             addr.get("land")]  # fmt: skip
    return ", ".join(p for p in parts if p)


def _no_company(row: dict[str, Any]) -> dict[str, Any]:
    number = row.get("organisasjonsnummer")
    flags = [label for key, label in (("konkurs", "bankrupt"), ("underAvvikling", "being wound up"),
             ("underTvangsavviklingEllerTvangsopplosning", "compulsory winding-up")) if row.get(key)]  # fmt: skip
    return _clean({
        "registry": "Norway (Brønnøysund)", "company_number": number, "legal_name": row.get("navn"),
        "company_status": ", ".join(flags) or ("deleted" if row.get("slettedato") else "active"),
        "insolvency": flags or None, "incorporated": row.get("stiftelsesdato"), "dissolved": row.get("slettedato"),
        "company_type": (row.get("organisasjonsform") or {}).get("beskrivelse"),
        "industry": (row.get("naeringskode1") or {}).get("beskrivelse"), "employees": row.get("antallAnsatte"),
        "registered_address": _no_address(row.get("forretningsadresse") or row.get("postadresse")),
        "website": row.get("hjemmeside"), "in_group": row.get("erIKonsern"), "country": "NO",
        "register_url": f"https://virksomhet.brreg.no/nb/oppslag/enheter/{number}" if number else None,
    })  # fmt: skip


class NorwayRegistryModule(_RegisterModule):
    name = "norway_registry"
    description = "Norway's company register: details, bankruptcy flags, managing director, board and auditor (free)"
    registry = "Norway (Brønnøysund)"
    url_setting = "norway_registry_url"

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        base = self.base()
        async with session.get(f"{base}/enheter", params={"navn": entity.value, "size": "10"}) as resp:
            if resp.status != 200:
                return
            rows = ((await resp.json(content_type=None)).get("_embedded") or {}).get("enheter") or []
        score, row = _best(entity.value, [(r.get("navn") or "", r) for r in rows])
        if row is None or score < MATCH:
            return
        entity.metadata.update(_no_company(row))
        async with session.get(f"{base}/enheter/{row['organisasjonsnummer']}/roller") as resp:
            if resp.status != 200:
                return
            groups = (await resp.json(content_type=None)).get("rollegrupper") or []
        count = 0
        for group in groups:
            for role in group.get("roller") or []:
                if role.get("avregistrert") or role.get("fratraadt") or count >= PEOPLE_LIMIT:
                    continue
                code = (role.get("type") or {}).get("kode") or ""
                label = NO_ROLES.get(code, (role.get("type") or {}).get("beskrivelse") or "role")
                if role.get("person"):
                    person = role["person"]
                    if person.get("erDoed"):
                        continue
                    n = person.get("navn") or {}
                    name = " ".join(p for p in (n.get("fornavn"), n.get("mellomnavn"), n.get("etternavn")) if p)
                    if name:
                        for item in self._person(
                            entity, person_name(name), {"role": label, "born": _born(person.get("fodselsdato"))}, label
                        ):
                            yield item
                        count += 1
                elif role.get("enhet"):
                    unit = role["enhet"]
                    raw = unit.get("navn")
                    name = company_name(" ".join(raw) if isinstance(raw, list) else str(raw or ""))
                    if name:
                        for item in self._organisation(entity, name, {"company_number": unit.get("organisasjonsnummer"),
                                                                     "role": label, "country": "NO"}, label):  # fmt: skip
                            yield item
                        count += 1


# ---------------------------------------------------------------------------- Finland
def _english(descriptions: list[dict[str, Any]] | None) -> str | None:
    rows = descriptions or []
    pick = next((d for d in rows if d.get("languageCode") == "3"), rows[0] if rows else None)
    return pick.get("description") if pick else None


def _fi_names(row: dict[str, Any]) -> tuple[str, list[str]]:
    names = row.get("names") or []
    current = [n["name"] for n in names if n.get("name") and not n.get("endDate") and str(n.get("type")) == "1"]
    former = [n["name"] for n in names if n.get("name") and n.get("endDate") and str(n.get("type")) == "1"]
    return (current[0] if current else (names[0].get("name") if names else "")), former


def _fi_company(row: dict[str, Any]) -> dict[str, Any]:
    name, former = _fi_names(row)
    number = (row.get("businessId") or {}).get("value")
    address = next((a for a in row.get("addresses") or [] if a.get("type") == 1), None)
    city = next((p.get("city") for p in (address or {}).get("postOffices") or [] if p.get("languageCode") == "1"), None)
    street = " ".join(str(x) for x in ((address or {}).get("street"), (address or {}).get("buildingNumber")) if x)
    situations = [_english(s.get("descriptions")) or s.get("type") for s in row.get("companySituations") or []]
    return _clean({
        "registry": "Finland (PRH)", "company_number": number, "legal_name": name, "former_names": former,
        "company_status": ", ".join(str(s) for s in situations if s) or "registered",
        "insolvency": [s for s in situations if s] or None,
        "incorporated": (row.get("businessId") or {}).get("registrationDate"),
        "company_type": _english(((row.get("companyForms") or [{}])[0]).get("descriptions")),
        "industry": _english((row.get("mainBusinessLine") or {}).get("descriptions")),
        "website": (row.get("website") or {}).get("url"), "country": "FI",
        "registered_address": ", ".join(p for p in (street, f"{(address or {}).get('postCode') or ''} {city or ''}".strip()) if p),
        "register_url": f"https://tietopalvelu.ytj.fi/yritys/{number}" if number else None,
    })  # fmt: skip


class FinlandRegistryModule(_RegisterModule):
    name = "finland_registry"
    description = (
        "Finland's company register: details, former names, line of business, bankruptcy or liquidation (free)"
    )
    registry = "Finland (PRH)"
    url_setting = "finland_registry_url"
    attack_techniques: ClassVar[tuple[str, ...]] = ("T1591.002",)

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        async with session.get(f"{self.base()}/companies", params={"name": entity.value}) as resp:
            if resp.status != 200:
                return
            rows = (await resp.json(content_type=None)).get("companies") or []
        score, row = _best(entity.value, [(_fi_names(r)[0], r) for r in rows[:50]])
        if row is None or score < MATCH:
            return
        entity.metadata.update(_fi_company(row))
        return
        yield  # an async generator that may yield nothing
