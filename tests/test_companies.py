"""Companies, sanctions and leaks: name matching, sanctions lists, registers, and Argus credits."""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from argus.accounts import connectors
from argus.core.models import Entity, EntityType, RelationType
from argus.core.settings import get_settings
from argus.intel import watchlists
from argus.intel.names import similarity
from tests.test_modules_offline import FakeResponse, FakeSession, collect

GOOD_PHRASE = "correct horse battery"  # a test account's pass phrase


# ---------------------------------------------------------------------------- names
@pytest.mark.parametrize("a, b, kind, low, high", [
    ("SMITH, John Paul", "John Smith", "person", 0.95, 1.0),
    ("Jóhn Smith", "John Smith", "person", 1.0, 1.0),
    ("J. Smith", "John Smith", "person", 0.9, 0.96),
    ("Vladimir Putin", "PUTIN, Vladimir Vladimirovich", "person", 0.95, 1.0),
    ("John Smith", "Johnson Smithers", "person", 0.0, 0.0),
    ("Jane Roe", "John Roe", "person", 0.0, 0.0),
    ("Smith", "John Smith", "person", 0.0, 0.0),  # one word never identifies a person
    ("Acme Holdings Limited", "ACME HOLDINGS LTD.", "company", 1.0, 1.0),
    ("Sberbank of Russia", "PUBLIC JOINT STOCK COMPANY SBERBANK OF RUSSIA", "company", 1.0, 1.0),
    ("Smith & Sons Ltd", "Smith and Sons Limited", "company", 1.0, 1.0),
    ("Acme Ltd", "Acmex Trading Ltd", "company", 0.0, 0.6),
    ("Apple Inc", "Pineapple Ltd", "company", 0.0, 0.8),
])  # fmt: skip
def test_name_matching(a, b, kind, low, high):
    assert low <= similarity(a, b, kind=kind) <= high


# ---------------------------------------------------------------------------- sanctions lists
OFAC = ('17,"PUTIN, Vladimir Vladimirovich","individual","RUSSIA-EO14024","President","-0- ","-0- ","-0- ","-0- ",'
        '"-0- ","-0- ","DOB 07 Oct 1952; POB Leningrad, Russia; nationality Russia; Gender Male."\n'
        '18,"SBERBANK","-0- ","RUSSIA-EO14024] [UKRAINE-EO13662","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ","-0- ",'
        '"Website www.sberbank.ru."\n')  # fmt: skip
OFAC_ALT = '18,101,"aka","PUBLIC JOINT STOCK COMPANY SBERBANK OF RUSSIA","-0- "\n'
UK_FCDO = ("Report Date: 15/11/2026\nLast Updated,Unique ID,OFSI Group ID,Name 6,Name 1,Name 2,Name 3,Name 4,Name 5,"
           "Name type,Designation Type,Regime Name,D.O.B,Nationality(/ies)\n"
           "01/01/2026,RUS0001,123,PUTIN,Vladimir,Vladimirovich,,,,Primary Name,Individual,Russia,07/10/1952,Russia\n"
           "01/01/2026,RUS0001,123,POUTINE,Vladimir,,,,,Alias,Individual,Russia,07/10/1952,Russia\n"
           "01/01/2026,RUS0099,999,SHELL TRADING LLP,,,,,,Primary Name,Entity,Russia,,\n")  # fmt: skip
UK_OFSI = ("Last Updated,10/11/2026\nName 6,Name 1,Name 2,Name 3,Name 4,Name 5,Title,DOB,Nationality,Regime,"
           "Group Type,Alias Type,Group ID\nDOE,Jane,,,,,,01/01/1970,Utopia,Global Human Rights,Individual,Primary name,555\n")  # fmt: skip
UN = (b"<CONSOLIDATED_LIST><INDIVIDUALS><INDIVIDUAL><DATAID>1</DATAID><FIRST_NAME>ABU</FIRST_NAME><SECOND_NAME>BAKR"
      b"</SECOND_NAME><UN_LIST_TYPE>Al-Qaida</UN_LIST_TYPE><REFERENCE_NUMBER>QDi.001</REFERENCE_NUMBER>"
      b"<INDIVIDUAL_ALIAS><ALIAS_NAME>Abu Bakar</ALIAS_NAME></INDIVIDUAL_ALIAS><INDIVIDUAL_DATE_OF_BIRTH><YEAR>1971</YEAR>"
      b"</INDIVIDUAL_DATE_OF_BIRTH></INDIVIDUAL></INDIVIDUALS><ENTITIES><ENTITY><DATAID>2</DATAID><FIRST_NAME>"
      b"EXAMPLE TRADING LLC</FIRST_NAME><UN_LIST_TYPE>DPRK</UN_LIST_TYPE><REFERENCE_NUMBER>KPe.001</REFERENCE_NUMBER>"
      b"</ENTITY></ENTITIES></CONSOLIDATED_LIST>")  # fmt: skip


def test_the_three_lists_are_read():
    ofac = watchlists.parse_ofac(OFAC, OFAC_ALT)
    putin = next(x for x in ofac if x.ref == "17")
    assert putin.kind == "person" and putin.details == {"Date of birth": "07 Oct 1952", "Place of birth": "Leningrad, Russia",
                                                       "Nationality": "Russia"}  # fmt: skip
    sber = next(x for x in ofac if x.ref == "18")
    assert sber.kind == "company" and sber.programs == ["RUSSIA-EO14024", "UKRAINE-EO13662"] and sber.aliases
    uk = watchlists.parse_uk(UK_FCDO)
    assert {(x.ref, x.name, x.kind) for x in uk} == {("RUS0001", "PUTIN, Vladimir Vladimirovich", "person"),
                                                      ("RUS0099", "SHELL TRADING LLP", "company")}  # fmt: skip
    assert next(x for x in uk if x.ref == "RUS0001").aliases == ["POUTINE, Vladimir"]
    old = watchlists.parse_uk(UK_OFSI)  # the previous OFSI layout is still understood
    assert (
        old[0].name == "DOE, Jane"
        and old[0].programs == ["Global Human Rights"]
        and old[0].details["Nationality"] == "Utopia"
    )
    un = watchlists.parse_un(UN)
    assert {(x.ref, x.kind) for x in un} == {("QDi.001", "person"), ("KPe.001", "company")}
    with pytest.raises(ValueError, match="header"):
        watchlists.parse_uk("not,a,sanctions,file\n")


@pytest.fixture
def lists_folder(tmp_path, monkeypatch):
    (tmp_path / "sdn.csv").write_text(OFAC, encoding="latin-1")
    (tmp_path / "alt.csv").write_text(OFAC_ALT, encoding="latin-1")
    (tmp_path / "UK-Sanctions-List.csv").write_text(UK_FCDO)
    (tmp_path / "consolidated.xml").write_bytes(UN)
    monkeypatch.setenv("ARGUS_SANCTIONS_FILE", str(tmp_path))
    get_settings.cache_clear()
    watchlists.reset()
    return tmp_path


async def test_screening_people_and_companies(lists_folder):
    await watchlists.load(FakeSession({}))
    assert watchlists.status()["sources"]["UN Consolidated List"] == {"status": "ok", "listings": 2}
    putin = watchlists.screen("Vladimir Putin", kind="person")
    assert {m["list"] for m in putin} == {"US OFAC SDN", "UK Sanctions List"}
    assert putin[0]["details"]["Date of birth"] and putin[0]["score"] >= 0.95
    assert watchlists.screen("Vladimir Poutine", kind="person")[0]["matched_name"] == "POUTINE, Vladimir"  # an alias
    assert watchlists.screen("Sberbank of Russia", kind="company")[0]["ref"] == "18"
    assert watchlists.screen("Example Trading Ltd", kind="company")[0]["list"] == "UN Consolidated List"
    assert watchlists.screen("John Smith", kind="person") == []
    assert watchlists.screen("Sberbank of Russia", kind="person") == []  # a company is never matched as a person


async def test_one_broken_list_does_not_stop_the_others(lists_folder):
    (lists_folder / "UK-Sanctions-List.csv").write_text("garbage")
    await watchlists.load(FakeSession({}))
    sources = watchlists.status()["sources"]
    assert sources["UK Sanctions List"]["status"] == "unavailable" and sources["US OFAC SDN"]["status"] == "ok"
    assert watchlists.screen("Vladimir Putin", kind="person")[0]["list"] == "US OFAC SDN"


async def test_people_and_companies_are_screened_in_scans(lists_folder):
    from argus.modules.corporate.registers import SanctionsScreenModule

    person = Entity.create(EntityType.PERSON, "Vladimir Putin")
    await collect(SanctionsScreenModule(), person, FakeSession({}))
    assert {m["list"] for m in person.metadata["sanction_matches"]} == {"US OFAC SDN", "UK Sanctions List"}
    namesake = Entity.create(
        EntityType.PERSON, "Vladimir Putin", metadata={"born": "1990-01", "nationality": "Finnish"}
    )
    await collect(SanctionsScreenModule(), namesake, FakeSession({}))
    conflicts = namesake.metadata["sanction_matches"][0]["conflicts"]
    assert conflicts == [
        "Born 1990, but the listed person was born 1952",
        "Nationality Finnish, but the listed person's is Russia",
    ]
    assert "conflicts" not in person.metadata["sanction_matches"][0]  # nothing known: nothing contradicts
    clean = Entity.create(EntityType.ORGANIZATION, "Harmless Bakery Ltd")
    await collect(SanctionsScreenModule(), clean, FakeSession({}))
    assert "sanction_matches" not in clean.metadata


# ---------------------------------------------------------------------------- the connector menu
def test_lookups_are_a_fixed_menu_not_a_proxy():
    url, query = connectors.build("companies_house", "officers", {"number": "1234567"})
    assert url == "https://api.company-information.service.gov.uk/company/01234567/officers"
    assert query == {"items_per_page": "35"}
    url, query = connectors.build("companies_house", "search_companies", {"q": "Acme / ../../admin"})
    assert url.endswith("/search/companies") and query["q"] == "Acme / ../../admin"  # free text stays a query value
    for provider, name, params in (("companies_house", "company", {"number": "../../etc"}),
                                   ("companies_house", "appointments", {"officer_id": "x/y"}),
                                   ("companies_house", "search_companies", {"q": ""}),
                                   ("companies_house", "delete_everything", {}), ("evil", "company", {})):  # fmt: skip
        with pytest.raises(connectors.ConnectError):
            connectors.build(provider, name, params)


# ---------------------------------------------------------------------------- Companies House
CH = "api.company-information.service.gov.uk"
COMPANY = {
    "company_name": "ACME WIDGETS LIMITED",
    "company_number": "01234567",
    "company_status": "active",
    "date_of_creation": "2015-03-01",
    "type": "ltd",
    "sic_codes": ["62020"],
    "registered_office_address": {"address_line_1": "1 High Street", "locality": "London", "postal_code": "N1 1AA"},
}
OFFICERS = {"items": [
    {"name": "ROE, Jane Mary", "officer_role": "director", "appointed_on": "2015-03-01", "nationality": "British",
     "date_of_birth": {"month": 4, "year": 1980}, "links": {"officer": {"appointments": "/officers/abcDEF123456/appointments"}}},
    {"name": "DOE, John", "officer_role": "secretary", "appointed_on": "2015-03-01", "resigned_on": "2019-01-01",
     "links": {"officer": {"appointments": "/officers/zzzYYY987654/appointments"}}},
    {"name": "NOMINEE SERVICES LTD", "officer_role": "corporate-director", "appointed_on": "2016-01-01",
     "links": {"officer": {"appointments": "/officers/corpCORP0001/appointments"}}},
]}  # fmt: skip
PSC = {"items": [
    {"kind": "individual-person-with-significant-control", "name": "Mrs Jane Mary Roe",
     "natures_of_control": ["ownership-of-shares-75-to-100-percent"], "notified_on": "2016-04-06", "nationality": "British"},
    {"kind": "corporate-entity-person-with-significant-control", "name": "OFFSHORE HOLDINGS SA",
     "natures_of_control": ["voting-rights-25-to-50-percent"]},
    {"kind": "super-secure-person-with-significant-control"},
]}  # fmt: skip
APPOINTMENTS = {"total_results": 2, "items": [
    {"appointed_to": {"company_name": "ACME WIDGETS LIMITED", "company_number": "01234567", "company_status": "active"},
     "officer_role": "director", "appointed_on": "2015-03-01"},
    {"appointed_to": {"company_name": "SHELL TRADING LLP", "company_number": "OC999999", "company_status": "dissolved"},
     "officer_role": "llp-designated-member", "appointed_on": "2018-02-02", "resigned_on": "2020-01-01"},
]}  # fmt: skip


def ch_session():
    return FakeSession({
        rf"{CH}/search/companies": FakeResponse(200, {"items": [{"title": "ACME WIDGETS LIMITED", "company_number": "01234567"},
                                                                {"title": "ACME WIDGETS (NORTH) LTD", "company_number": "07654321"}]}),
        rf"{CH}/company/01234567$": FakeResponse(200, COMPANY),
        rf"{CH}/company/01234567/officers": FakeResponse(200, OFFICERS),
        rf"{CH}/company/01234567/persons-with-significant-control": FakeResponse(200, PSC),
        rf"{CH}/officers/abcDEF123456/appointments": FakeResponse(200, APPOINTMENTS),
        rf"{CH}/search/officers": FakeResponse(200, {"items": [
            {"title": "Jane Mary ROE", "date_of_birth": {"month": 4, "year": 1980}, "appointment_count": 2,
             "links": {"self": "/officers/abcDEF123456/appointments"}},
            {"title": "Janet ROSS", "links": {"self": "/officers/other0000001/appointments"}}]}),
    })  # fmt: skip


@pytest.fixture
def own_key(monkeypatch):
    monkeypatch.setenv("ARGUS_COMPANIES_HOUSE_API_KEY", "test-key")
    monkeypatch.setenv("ARGUS_COMPANIES_HOUSE_OFFICER_LIMIT", "1")
    get_settings.cache_clear()


async def test_a_company_with_its_directors_and_owners(own_key):
    from argus.modules.corporate.companies_house import CompaniesHouseModule

    assert CompaniesHouseModule.is_configured()
    seed = Entity.create(EntityType.ORGANIZATION, "Acme Widgets Ltd")
    entities, relations = await collect(CompaniesHouseModule(), seed, ch_session())
    md = seed.metadata
    assert (md["company_number"], md["company_status"], md["incorporated"]) == ("01234567", "active", "2015-03-01")
    assert md["registered_address"] == "1 High Street, London, N1 1AA" and md["register_url"].endswith(
        "/company/01234567"
    )
    people = {e.value: e for e in entities}
    jane = people["Jane Mary Roe"]
    assert (
        jane.type == EntityType.PERSON
        and jane.metadata["born"] == "1980-04"
        and jane.metadata["ch_officer_id"] == "abcDEF123456"
    )
    assert "ch_officer_id" not in people["John Doe"].metadata  # resigned: not followed (and the limit is 1)
    assert people["Nominee Services LTD"].type == EntityType.ORGANIZATION
    roles = {(r.label, r.metadata.get("to")) for r in relations if r.type == RelationType.OFFICER_OF}
    assert ("director", None) in roles and ("secretary (resigned)", "2019-01-01") in roles
    controls = [r for r in relations if r.type == RelationType.CONTROLS]
    assert len(controls) == 2 and controls[0].metadata["nature"] == ["ownership of shares 75 to 100 percent"]
    assert people["Offshore Holdings SA"].type == EntityType.ORGANIZATION
    assert "Mrs Jane Mary Roe" in people  # owners keep the name as the register gives it


async def test_a_directors_other_companies(own_key):
    from argus.modules.corporate.companies_house import CompaniesHouseModule

    jane = Entity.create(EntityType.PERSON, "Jane Mary Roe", depth=1, metadata={"ch_officer_id": "abcDEF123456"})
    entities, relations = await collect(CompaniesHouseModule(), jane, ch_session())
    assert {e.value for e in entities} == {"Acme Widgets Limited", "Shell Trading LLP"}
    found_via = Entity.create(EntityType.PERSON, "Jane Mary Roe", depth=1,
                              metadata={"ch_officer_id": "abcDEF123456", "ch_company": "01234567"})  # fmt: skip
    again, _ = await collect(CompaniesHouseModule(), found_via, ch_session())
    assert {e.value for e in again} == {"Shell Trading LLP"}  # the company she was found through is not duplicated
    assert jane.metadata["appointments_total"] == 2
    assert any(r.label == "llp designated member (resigned)" for r in relations)


async def test_a_name_typed_in_gives_possible_matches(own_key):
    from argus.modules.corporate.companies_house import CompaniesHouseModule

    seed = Entity.create(EntityType.PERSON, "Jane Roe")
    entities, _ = await collect(CompaniesHouseModule(), seed, ch_session())
    assert [m["name"] for m in seed.metadata["officer_matches"]] == ["Jane Mary Roe"]  # not Janet Ross
    assert entities and all(e.confidence == 0.5 for e in entities)  # possibly the same person: weak links
    assert {e.metadata["via_possible_match"] for e in entities} == {"Jane Mary Roe (born 1980-04)"}


async def test_no_exact_company_shows_candidates_only(own_key):
    from argus.modules.corporate.companies_house import CompaniesHouseModule

    seed = Entity.create(EntityType.ORGANIZATION, "Acme Gadgets Ltd")
    entities, _ = await collect(CompaniesHouseModule(), seed, ch_session())
    assert entities == [] and seed.metadata["registry_candidates"][0]["number"] == "01234567"


def test_companies_house_needs_a_key_or_an_account(monkeypatch):
    from argus.modules.corporate.companies_house import CompaniesHouseModule

    monkeypatch.delenv("ARGUS_COMPANIES_HOUSE_API_KEY", raising=False)
    get_settings.cache_clear()
    assert not CompaniesHouseModule.is_configured()
    monkeypatch.setenv("ARGUS_EDITION", "personal")
    monkeypatch.setenv("ARGUS_ACCOUNT_SERVER_URL", "https://accounts.test")
    get_settings.cache_clear()
    assert CompaniesHouseModule.is_configured()  # Argus Personal: through Argus Connect


class PostingSession(FakeSession):
    def __init__(self, routes, answer):
        super().__init__(routes)
        self.answer, self.posted = answer, []

    def post(self, url, **kwargs):
        self.posted.append((url, kwargs.get("json")))
        return FakeSession({".": self.answer}).get(url)


async def test_modules_use_argus_connect_without_a_key(monkeypatch):
    from argus.accounts import connect_client, personal

    monkeypatch.delenv("ARGUS_COMPANIES_HOUSE_API_KEY", raising=False)
    monkeypatch.setenv("ARGUS_EDITION", "personal")
    monkeypatch.setenv("ARGUS_ACCOUNT_SERVER_URL", "https://accounts.test")
    get_settings.cache_clear()

    class Licence:
        token, last_credits = "argus1.x.y", None

    monkeypatch.setattr(personal, "CURRENT", Licence())
    session = PostingSession({}, FakeResponse(200, {"result": COMPANY, "credits": {"charged": 1, "available": 49}}))
    result = await connect_client.lookup(session, "companies_house", "company", {"number": "01234567"})
    assert result == COMPANY and personal.CURRENT.last_credits["available"] == 49
    assert session.posted[0] == ("https://accounts.test/api/connect/companies_house",
                                 {"licence": "argus1.x.y", "operation": "company", "params": {"number": "01234567"}})  # fmt: skip
    broke = PostingSession({}, FakeResponse(402, {"detail": "Not enough Argus credits for this lookup"}))
    with pytest.raises(connectors.ConnectError, match="Not enough Argus credits"):
        await connect_client.lookup(broke, "companies_house", "company", {"number": "01234567"})


# ---------------------------------------------------------------------------- free registers and leaks
async def test_gleif_finds_the_company_and_its_parents():
    from argus.modules.corporate.registers import GleifModule

    record = lambda lei, name: {"id": lei, "attributes": {"lei": lei, "entity": {"legalName": {"name": name},  # noqa: E731
                                "jurisdiction": "GB", "status": "ACTIVE", "legalAddress": {"addressLines": ["1 High St"],
                                "city": "London", "country": "GB"}}, "registration": {"status": "ISSUED"}}}  # fmt: skip
    session = FakeSession({
        r"/lei-records\?|/lei-records$": FakeResponse(200, {"data": [record("LEI000000000000000AC", "ACME WIDGETS LIMITED")]}),
        r"/direct-parent$": FakeResponse(200, {"data": record("LEI000000000000000PA", "ACME GROUP HOLDINGS PLC")}),
        r"/ultimate-parent$": FakeResponse(200, {"data": record("LEI000000000000000UL", "GLOBAL ACME SA")}),
    })  # fmt: skip
    seed = Entity.create(EntityType.ORGANIZATION, "Acme Widgets Ltd")
    entities, relations = await collect(GleifModule(), seed, session)
    assert (
        seed.metadata["lei"] == "LEI000000000000000AC"
        and seed.metadata["registered_address"] == "1 High St, London, GB"
    )
    assert {e.value for e in entities} == {"Acme Group Holdings PLC", "Global Acme SA"}
    assert {r.label for r in relations} == {"Direct parent", "Ultimate parent"}


async def test_sec_edgar_and_offshore_leaks(monkeypatch):
    from argus.modules.corporate import registers

    monkeypatch.setenv("ARGUS_SEC_USER_AGENT", "Argus Tests tests@example.org")
    get_settings.cache_clear()
    registers._tickers.update(loaded=0.0, rows=[])
    session = FakeSession({
        r"company_tickers\.json": FakeResponse(200, {"0": {"cik_str": 320193, "ticker": "ACME", "title": "Acme Widgets Inc"}}),
        r"submissions/CIK0000320193\.json": FakeResponse(200, {"name": "ACME WIDGETS INC", "sicDescription": "Widgets",
            "stateOfIncorporation": "DE", "formerNames": [{"name": "ACME CORP"}],
            "filings": {"recent": {"form": ["10-K", "8-K"], "filingDate": ["2026-02-01", "2026-01-10"]}}}),
        r"/api/v1/reconcile": FakeResponse(200, {"q0": {"result": [{"id": 12000001, "name": "Acme Widgets Ltd", "score": 99},
                                                                   {"id": 12000002, "name": "Acme Gadgets SA", "score": 60}]}}),
    })  # fmt: skip
    seed = Entity.create(EntityType.ORGANIZATION, "Acme Widgets Ltd")
    await collect(registers.SecEdgarModule(), seed, session)
    md = seed.metadata
    assert (md["sec_cik"], md["ticker"], md["state_of_incorporation"]) == ("0000320193", "ACME", "DE")
    assert md["former_names"] == ["ACME CORP"] and md["recent_filings"][0] == {"form": "10-K", "date": "2026-02-01"}
    await collect(registers.OffshoreLeaksModule(), seed, session)
    assert [h["name"] for h in md["offshore_leaks"]] == ["Acme Widgets Ltd"]
    assert md["offshore_leaks"][0]["url"].endswith("/nodes/12000001") and "ODbL" in md["offshore_leaks_credit"]


def test_names_are_recognised_as_targets():
    from argus.cli.console import detect_target_type

    assert detect_target_type("Acme Holdings Ltd") == EntityType.ORGANIZATION
    assert detect_target_type("Jane Roe") == EntityType.PERSON
    assert detect_target_type("jane_roe") == EntityType.USERNAME


# ---------------------------------------------------------------------------- Argus credits
class FakeCompaniesHouse(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        self.calls: list[tuple[str, str]] = []
        super().__init__(("127.0.0.1", 0), CHHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class CHHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.calls.append((self.path, self.headers.get("Authorization", "")))
        if "/company/01234567" in self.path:
            status, body = 200, COMPANY
        elif "/company/09999999" in self.path:
            status, body = 500, {"error": "boom"}
        else:
            status, body = 404, {}
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


@pytest.fixture
def broker(make_client, monkeypatch):
    from argus.accounts.licence import generate_keypair
    from argus.api import account_routes, connect_routes
    from argus.security.ratelimit import SlidingWindowLimiter

    ch = FakeCompaniesHouse()
    monkeypatch.setitem(connectors.BASES, "companies_house", ch.url)
    monkeypatch.setattr(account_routes, "_per_ip", SlidingWindowLimiter(limit=50, window=60))
    monkeypatch.setattr(account_routes, "_signups", SlidingWindowLimiter(limit=50, window=3600))
    monkeypatch.setattr(connect_routes, "_per_account", SlidingWindowLimiter(limit=500, window=60))
    private, _public = generate_keypair()
    c = make_client(account_service_enabled="true", licence_signing_key=private, account_signup_enabled="true",
                    public_url="http://testserver", monitors_enabled="false", companies_house_api_key="central-key")  # fmt: skip
    c.post("/api/accounts/signup", json={"email": "jane@example.org", "password": GOOD_PHRASE})
    licence = c.post("/api/accounts/token", json={"email": "jane@example.org", "password": GOOD_PHRASE,
                                                  "device_id": "device-0123456789abcdef"}).json()["licence"]  # fmt: skip
    yield c, ch, licence
    ch.shutdown()


def lookup(c, licence, operation="company", **params: Any):
    return c.post("/api/connect/companies_house", json={"licence": licence, "operation": operation,
                                                         "params": params or {"number": "01234567"}})  # fmt: skip


def test_credits_pay_for_brokered_lookups(broker):
    c, ch, licence = broker
    balance = c.post("/api/connect/balance", json={"licence": licence}).json()
    assert balance["credits"] == {"allowance": 50, "allowance_remaining": 50, "purchased": 0, "available": 50,
                                  "month": datetime.now(timezone.utc).strftime("%Y-%m")}  # fmt: skip
    assert balance["prices"]["companies_house"]["lookups"]["officers"] == 1
    r = lookup(c, licence)
    assert r.status_code == 200 and r.json()["result"]["company_name"] == "ACME WIDGETS LIMITED"
    assert r.json()["credits"] == {"charged": 1, "available": 49, "allowance_remaining": 49, "purchased": 0}
    assert ch.calls[0][1].startswith("Basic ")  # the operator's key, never the customer's
    not_found = lookup(c, licence, number="00000001")
    assert not_found.json()["result"] == {"not_found": True} and not_found.json()["credits"]["charged"] == 0
    failed = lookup(c, licence, number="09999999")
    assert failed.status_code == 502
    refused = lookup(c, licence, number="../../admin")
    assert refused.status_code == 422 and len(ch.calls) == 3  # invalid details never reach the source
    assert c.post("/api/connect/balance", json={"licence": licence}).json()["credits"]["available"] == 49  # refunds


def test_running_out_and_buying_more(broker, monkeypatch):
    from argus.accounts import licence as lic

    c, _ch, licence = broker
    account_id = lic.verify(
        licence, lic.load_private_key(c.app.state.settings.licence_signing_key.get_secret_value()).public_key()
    )["sub"]
    monkeypatch.setitem(lic.PLANS, "trial", {**lic.PLANS["trial"], "monthly_credits": 1})
    c.app.state.subscribers  # noqa: B018 - the same app serves the admin endpoints
    adjust = c.post(f"/api/accounts/{account_id}/credits", json={"amount": -100, "kind": "adjustment"})
    assert adjust.status_code == 200 and adjust.json()["purchased"] == 0
    for _ in range(50):
        if lookup(c, licence).status_code == 402:
            break
    out = lookup(c, licence)
    assert out.status_code == 402 and "Not enough Argus credits" in out.json()["detail"]
    bought = c.post(
        f"/api/accounts/{account_id}/credits", json={"amount": 10, "kind": "purchase", "detail": "pack of 10"}
    )
    assert bought.json()["purchased"] == 10
    paid = lookup(c, licence)
    assert paid.status_code == 200 and paid.json()["credits"]["purchased"] == 9  # allowance spent: purchased used
    ledger = c.get(f"/api/accounts/{account_id}/credits").json()["ledger"]
    kinds = [row["kind"] for row in ledger]
    assert {"allowance", "usage", "purchase", "adjustment"} <= set(kinds) and ledger[0][
        "detail"
    ] == "companies_house/company"
    assert all("01234567" not in row["detail"] for row in ledger)  # what was looked up is not kept


def test_only_current_subscribers_on_this_computer_can_spend(broker):
    from argus.accounts import licence as lic

    c, _ch, licence = broker
    account_id = lic.verify(
        licence, lic.load_private_key(c.app.state.settings.licence_signing_key.get_secret_value()).public_key()
    )["sub"]
    c.patch(f"/api/accounts/{account_id}", json={"status": "cancelled"})
    assert lookup(c, licence).status_code == 402
    c.patch(f"/api/accounts/{account_id}", json={"status": "active"})
    c.post("/api/accounts/sign-out", json={"licence": licence})
    assert lookup(c, licence).status_code == 401
    assert lookup(c, "argus1.forged.licence").status_code == 401


def test_a_new_month_renews_the_allowance(broker):
    from functools import partial

    from argus.accounts import licence as lic

    c, _ch, licence = broker
    key = lic.load_private_key(c.app.state.settings.licence_signing_key.get_secret_value())
    account_id = lic.verify(licence, key.public_key())["sub"]
    credits = c.app.state.credits
    january = datetime(2027, 1, 15, tzinfo=timezone.utc)
    first = c.portal.call(partial(credits.charge, account_id, 30, "companies_house/company", now=january))
    assert first["allowance_remaining"] == 20
    february = datetime(2027, 2, 2, tzinfo=timezone.utc)
    renewed = c.portal.call(partial(credits.balance, account_id, now=february))
    assert (
        renewed["allowance_remaining"] == 50 and renewed["month"] == "2027-02"
    )  # unused allowance does not carry over
    assert re.fullmatch(r"\d{4}-\d{2}", renewed["month"])
