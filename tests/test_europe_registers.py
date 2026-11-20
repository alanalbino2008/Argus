"""European company registers (France, Norway, Finland), against recorded answers from each.

The fixtures are real responses from each register, with the people's names and dates of birth
replaced by invented ones.
"""

from __future__ import annotations

import json
from pathlib import Path

from argus.core.models import Entity, EntityType, Relation
from argus.modules.corporate import company_name, person_name
from argus.modules.corporate.europe import FinlandRegistryModule, FranceRegistryModule, NorwayRegistryModule
from tests.test_modules_offline import FakeResponse, FakeSession, collect

DATA = Path(__file__).parent / "data" / "registers"


def answer(name: str) -> FakeResponse:
    return FakeResponse(200, json.loads((DATA / name).read_text(encoding="utf-8")))


def test_names_are_written_properly():
    assert person_name("CHAPOULAUD-FLOQUET, VALERIE") == "Valerie Chapoulaud-Floquet"
    assert person_name("O'BRIEN, SEAN") == "Sean O'Brien"
    assert company_name("COMPAGNIE DE SAINT-GOBAIN") == "Compagnie De Saint-Gobain"


async def test_france_a_company_and_its_directors():
    session = FakeSession({r"/search": answer("fr_company.json")})
    seed = Entity.create(EntityType.ORGANIZATION, "Danone")
    entities, relations = await collect(FranceRegistryModule(), seed, session)
    md = seed.metadata
    assert (md["registry"], md["company_number"], md["company_status"]) == (
        "France (SIRENE / RNE)",
        "552032534",
        "active",
    )
    assert md["register_url"].endswith("/552032534") and md["registered_address"].startswith("59-61 RUE LA FAYETTE")
    people = {e.value: e.metadata for e in entities if e.type == EntityType.PERSON}
    assert people["Claire Martin"]["born"] == "1971-03" and "chief executive" in people["Claire Martin"]["role"]
    assert "Anne Leroy-Petit" in people
    auditor = next(e for e in entities if e.type == EntityType.ORGANIZATION)
    assert auditor.value == "Pricewaterhousecoopers Audit" and "statutory auditor" in auditor.metadata["role"]
    assert all(isinstance(r, Relation) for r in relations) and len(relations) == len(entities)


async def test_france_a_persons_directorships():
    seed = Entity.create(EntityType.PERSON, "Claire Martin", metadata={"born": "1971-03"})
    entities, relations = await collect(
        FranceRegistryModule(), seed, FakeSession({r"/search": answer("fr_person.json")})
    )
    assert seed.metadata["french_directorships"] == 3
    sure = [e for e in entities if e.confidence >= 0.9]
    assert len(sure) == 2 and all(e.metadata["matched_person"]["how"] == "same name and month of birth" for e in sure)
    other = next(e for e in entities if e.confidence < 0.9)
    assert other.metadata["matched_person"]["born"] == "1958-02"  # same name, different person: shown as possible
    assert {r.label for r in relations} >= {"president (Président)", "board member (Administrateur)"}
    # without a known month of birth, every match is only a possibility
    plain = Entity.create(EntityType.PERSON, "Claire Martin")
    found, _ = await collect(FranceRegistryModule(), plain, FakeSession({r"/search": answer("fr_person.json")}))
    assert all(e.confidence == 0.6 for e in found)


async def test_france_needs_a_close_name_match():
    seed = Entity.create(EntityType.ORGANIZATION, "Danube Shipping Partners")
    entities, _ = await collect(FranceRegistryModule(), seed, FakeSession({r"/search": answer("fr_company.json")}))
    assert entities == [] and "registry" not in seed.metadata


async def test_norway_a_company_its_board_and_auditor():
    session = FakeSession({r"/roller$": answer("no_roles.json"), r"/enheter": answer("no_company.json")})
    seed = Entity.create(EntityType.ORGANIZATION, "Equinor ASA")
    entities, _ = await collect(NorwayRegistryModule(), seed, session)
    md = seed.metadata
    assert (md["company_number"], md["company_status"], md["website"]) == ("923609016", "active", "www.equinor.com")
    assert md["registered_address"] == "Forusbeen 50, 4035 STAVANGER, Norge"
    roles = [(e.value, e.metadata.get("role"), e.metadata.get("born")) for e in entities]
    assert ("Kari Nordmann", "managing director", "1970-02") in roles  # month and year only
    assert ("Ola Hansen", "chair of the board", "1962-07") in roles
    assert ("Ernst & Young AS", "auditor", None) in roles
    assert sum(1 for r in roles if r[0] == "Ingrid Berg") == 2  # the role of the one marked deceased is left out
    assert all(len(e.metadata.get("born") or "") in (0, 7) for e in entities)


async def test_norway_bankruptcy_is_shown():
    data = json.loads((DATA / "no_company.json").read_text(encoding="utf-8"))
    data["_embedded"]["enheter"][0].update(konkurs=True, underAvvikling=True)
    seed = Entity.create(EntityType.ORGANIZATION, "Equinor ASA")
    await collect(NorwayRegistryModule(), seed, FakeSession({r"/enheter": FakeResponse(200, data)}))
    assert seed.metadata["company_status"] == "bankrupt, being wound up"


async def test_finland_a_company():
    seed = Entity.create(EntityType.ORGANIZATION, "Supercell Oy")
    entities, _ = await collect(FinlandRegistryModule(), seed, FakeSession({r"/companies": answer("fi_company.json")}))
    md = seed.metadata
    assert entities == [] and md["company_number"] == "2336509-6" and md["company_type"] == "Limited company"
    assert md["registered_address"] == "Jätkäsaarenlaituri 1, 00180 HELSINKI" and md["website"] == "www.supercell.com"


def test_one_country_at_a_time(monkeypatch):
    uk = Entity.create(EntityType.ORGANIZATION, "Acme Ltd", metadata={"registry": "UK Companies House"})
    fresh = Entity.create(EntityType.ORGANIZATION, "Acme Ltd")
    far = Entity.create(EntityType.ORGANIZATION, "Acme Ltd")
    far.depth = 2
    for module in (FranceRegistryModule(), NorwayRegistryModule(), FinlandRegistryModule()):
        assert module.can_handle(fresh) and not module.can_handle(uk) and not module.can_handle(far)
    monkeypatch.setattr("argus.core.settings.get_settings", lambda: type("S", (), {"france_registry_url": ""})())
    from argus.modules.corporate import europe

    monkeypatch.setattr(europe, "get_settings", lambda: type("S", (), {"france_registry_url": ""})())
    assert not FranceRegistryModule().can_handle(fresh)  # switched off with an empty address
