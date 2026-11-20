"""OpenCorporates, UK Gazette insolvency notices and US court cases (CourtListener)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from argus.accounts import connect_client, connectors, own_keys
from argus.core.models import Entity, EntityType
from argus.modules.corporate.opencorporates import OpenCorporatesModule
from argus.modules.legal.courts import CourtRecordsModule
from argus.modules.legal.gazette import GazetteInsolvencyModule, notices
from tests.test_modules_offline import FakeResponse, FakeSession, collect

DATA = Path(__file__).parent / "data" / "registers"


class KeySession(FakeSession):
    """Records the query parameters and headers of each request (to check how keys are sent)."""

    def __init__(self, routes: dict[str, FakeResponse]):
        super().__init__(routes)
        self.sent: list[dict[str, Any]] = []

    def get(self, url: str, **kw: Any):
        self.sent.append({"url": url, "params": kw.get("params") or {}, "headers": kw.get("headers") or {}})
        return super().get(url, **kw)


@pytest.fixture
def own(monkeypatch):
    """Lookups with the investigator's own keys (direct, no credits)."""
    monkeypatch.setitem(own_keys._keys, "opencorporates", "oc-key-123456")
    monkeypatch.setitem(own_keys._keys, "courtlistener", "cl-key-123456")
    yield
    own_keys._keys.clear()


# ---------------------------------------------------------------------------- the connector
def test_lookups_are_built_safely():
    url, query = connectors.build("opencorporates", "company", {"jurisdiction": "gb", "number": "00445790"})
    assert url == "https://api.opencorporates.com/v0.4/companies/gb/00445790" and query == {}
    url, _ = connectors.build("opencorporates", "company", {"jurisdiction": "us_de", "number": "123"})
    assert url.endswith("/companies/us_de/123")  # not padded like a UK number
    for bad in (
        {"jurisdiction": "../x", "number": "1"},
        {"jurisdiction": "gb", "number": "a/../../b"},
        {"jurisdiction": "gb", "number": "a..b"},
        {"jurisdiction": "gb", "number": "a/b"},
    ):
        with pytest.raises(connectors.ConnectError):
            connectors.build("opencorporates", "company", bad)
    url, query = connectors.build("courtlistener", "dockets", {"q": '"Acme Corp"'})
    assert url == "https://www.courtlistener.com/api/rest/v4/search/" and query["type"] == "r"


async def test_keys_go_where_each_source_expects(own):
    session = KeySession({r"opencorporates": FakeResponse(200, {"results": {"companies": []}}),
                          r"courtlistener": FakeResponse(200, {"results": [], "count": 0})})  # fmt: skip
    await connect_client.lookup(session, "opencorporates", "search_companies", {"q": "Acme"})
    await connect_client.lookup(session, "courtlistener", "dockets", {"q": "Acme"})
    oc, cl = session.sent
    assert oc["params"]["api_token"] == "oc-key-123456" and "Authorization" not in oc["headers"]
    assert cl["headers"]["Authorization"] == "Token cl-key-123456" and "api_token" not in cl["params"]


# ---------------------------------------------------------------------------- OpenCorporates
def oc_company(name, number, jurisdiction="gb", **extra):
    return {"name": name, "company_number": number, "jurisdiction_code": jurisdiction,
            "opencorporates_url": f"https://opencorporates.com/companies/{jurisdiction}/{number}", **extra}  # fmt: skip


async def test_opencorporates_a_company_and_its_officers(own):
    search = {"results": {"companies": [{"company": oc_company("ACME WIDGETS GMBH", "HRB 1234", "de")},
                                        {"company": oc_company("ACME WIDGETS LLC", "555", "us_de")},
                                        {"company": oc_company("ACMEX TRADING LTD", "999")}]}}  # fmt: skip
    detail = {"results": {"company": oc_company(
        "ACME WIDGETS GMBH", "HRB 1234", "de", current_status="Active", incorporation_date="2001-04-01",
        registered_address_in_full="Hauptstr. 1, Berlin", registry_url="https://www.handelsregister.de/x",
        previous_names=[{"company_name": "ACME TOOLS GMBH"}],
        officers=[{"officer": {"name": "ERIKA MUSTERMANN", "position": "Geschäftsführer", "start_date": "2010-01-01"}},
                  {"officer": {"name": "MAX MUSTERMANN", "position": "Geschäftsführer", "end_date": "2015-01-01"}}])}}  # fmt: skip
    session = FakeSession(
        {r"/companies/search": FakeResponse(200, search), r"/companies/de/": FakeResponse(200, detail)}
    )
    seed = Entity.create(EntityType.ORGANIZATION, "Acme Widgets GmbH")
    entities, relations = await collect(OpenCorporatesModule(), seed, session)
    md = seed.metadata
    assert md["registry"] == "OpenCorporates (DE)" and md["company_number"] == "HRB 1234" and md["country"] == "DE"
    assert md["former_names"] == ["ACME TOOLS GMBH"] and md["register_url"] == "https://www.handelsregister.de/x"
    assert [e.value for e in entities] == ["Erika Mustermann"]  # current officers only
    assert relations[0].label == "Geschäftsführer"
    assert [c["jurisdiction"] for c in md["same_name_elsewhere"]] == ["us_de"]  # the investigator is told


async def test_opencorporates_only_the_scans_own_target_and_not_twice():
    module = OpenCorporatesModule()
    known = Entity.create(EntityType.ORGANIZATION, "Danone", metadata={"registry": "France (SIRENE / RNE)"})
    deeper = Entity.create(EntityType.ORGANIZATION, "Acme Ltd")
    deeper.depth = 1
    assert not module.can_handle(known) and not module.can_handle(deeper)
    assert module.can_handle(Entity.create(EntityType.ORGANIZATION, "Acme Ltd"))


async def test_opencorporates_a_persons_companies(own):
    found = {"results": {"officers": [
        {"officer": {"name": "ERIKA MUSTERMANN", "position": "director", "company": oc_company("ACME WIDGETS GMBH", "HRB 1234", "de")}},
        {"officer": {"name": "ERIKA MÜLLER", "position": "director", "company": oc_company("OTHER GMBH", "HRB 9", "de")}},
    ]}}  # fmt: skip
    seed = Entity.create(EntityType.PERSON, "Erika Mustermann")
    entities, _relations = await collect(
        OpenCorporatesModule(), seed, FakeSession({r"/officers/search": FakeResponse(200, found)})
    )
    assert [e.value for e in entities] == ["Acme Widgets GmbH"] and entities[0].confidence == 0.6
    assert entities[0].metadata["matched_person"]["how"].startswith("same name only")
    assert seed.metadata["opencorporates_officer_matches"] == 1


# ---------------------------------------------------------------------------- The Gazette
def test_reading_gazette_notices():
    data = json.loads((DATA / "gazette_company.json").read_text())
    found = notices(data)
    assert found[0] == {**found[0], "type": "Winding-Up Orders", "about": "CARILLION PLC", "date": "2018-01-19",
                        "url": "https://www.thegazette.co.uk/notice/2948343", "personal": False}  # fmt: skip
    assert found[1]["personal"] is True


async def test_gazette_a_companys_insolvency():
    session = KeySession(
        {r"/insolvency/notice/data.json": FakeResponse(200, json.loads((DATA / "gazette_company.json").read_text()))}
    )
    seed = Entity.create(EntityType.ORGANIZATION, "Carillion plc")
    await collect(GazetteInsolvencyModule(), seed, session)
    md = seed.metadata
    assert [n["type"] for n in md["insolvency_notices"]] == ["Winding-Up Orders"]  # not a director's bankruptcy
    assert md["insolvency_notice_match"] == "exact name in the notice"
    assert session.sent[0]["params"]["text"] == '"Carillion plc"'  # the exact name, as a phrase


async def test_gazette_people_are_possible_matches_and_other_countries_are_skipped():
    data = {"entry": [{"title": "SMITH, John", "published": "2019-05-02T09:00:00", "category": {"@term": "Bankruptcy Orders"},
                       "link": [{"@href": "https://www.thegazette.co.uk/notice/1"}]}], "f:total": "1"}  # fmt: skip
    seed = Entity.create(EntityType.PERSON, "John Smith")
    await collect(GazetteInsolvencyModule(), seed, FakeSession({r"data.json": FakeResponse(200, data)}))
    assert seed.metadata["insolvency_notices"][0]["type"] == "Bankruptcy Orders"
    assert seed.metadata["insolvency_notice_match"].startswith("same name only")
    french = Entity.create(EntityType.ORGANIZATION, "Danone", metadata={"country": "FR"})
    assert not GazetteInsolvencyModule().can_handle(french)
    empty = Entity.create(EntityType.ORGANIZATION, "Zzqx Widgets Limited")
    await collect(GazetteInsolvencyModule(), empty, FakeSession({r"data.json": FakeResponse(200, {"f:total": "0"})}))
    assert empty.metadata == {"insolvency_notices_checked": True}


# ---------------------------------------------------------------------------- CourtListener
DOCKETS = {"count": 41, "results": [
    {"caseName": "Acme Corp v. Roadrunner Inc.", "court": "District Court, D. Arizona", "dateFiled": "2021-03-04",
     "docketNumber": "2:21-cv-00123", "suitNature": "Contract", "docket_absolute_url": "/docket/1/acme-v-roadrunner/",
     "party": ["Acme Corp", "Roadrunner Inc."]},
    {"caseName": "Wile v. Coyote", "court": "District Court, D. Nevada", "dateFiled": "2020-01-01",
     "docketNumber": "1:20-cv-1", "docket_absolute_url": "/docket/2/wile-v-coyote/", "party": ["E. Wile", "Coyote LLC"]},
]}  # fmt: skip


async def test_court_cases_naming_a_company(own):
    seed = Entity.create(EntityType.ORGANIZATION, "Acme Corp")
    await collect(CourtRecordsModule(), seed, FakeSession({r"courtlistener": FakeResponse(200, DOCKETS)}))
    cases = seed.metadata["court_cases"]
    assert len(cases) == 1 and cases[0] == {"name": "Acme Corp v. Roadrunner Inc.", "court": "District Court, D. Arizona",
                                            "filed": "2021-03-04", "docket": "2:21-cv-00123", "nature": "Contract",
                                            "kind": "docket", "url": "https://www.courtlistener.com/docket/1/acme-v-roadrunner/"}  # fmt: skip
    assert seed.metadata["court_cases_total"] == 41 and "court_case_match" not in seed.metadata


async def test_court_cases_for_a_person_are_possible_matches(own):
    data = {"count": 1, "results": [{"caseName": "United States v. Smith", "dateFiled": "2019-01-01",
                                     "party": ["United States", "John Smith"], "docket_absolute_url": "/docket/3/"}]}  # fmt: skip
    seed = Entity.create(EntityType.PERSON, "John Smith")
    await collect(CourtRecordsModule(), seed, FakeSession({r"courtlistener": FakeResponse(200, data)}))
    assert seed.metadata["court_cases"][0]["name"] == "United States v. Smith"
    assert seed.metadata["court_case_match"].startswith("same name only")


def test_paid_sources_appear_only_with_a_key_or_an_account(monkeypatch):
    own_keys._keys.clear()
    assert not OpenCorporatesModule.is_configured() and not CourtRecordsModule.is_configured()
    monkeypatch.setitem(own_keys._keys, "courtlistener", "cl-key-123456")
    assert CourtRecordsModule.is_configured()
    own_keys._keys.clear()
    assert {p["provider"] for p in own_keys.listing()} >= {"opencorporates", "courtlistener"}
