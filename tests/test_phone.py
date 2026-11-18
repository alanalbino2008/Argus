"""Phone footprint: what a number says about itself, and where the web mentions it."""

from __future__ import annotations

import pytest

from argus.accounts import connectors
from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType
from argus.core.settings import get_settings
from argus.intel import playbooks
from argus.modules.identity.phone_recon import PhoneReconModule, describe
from argus.modules.identity.web_mentions import WebMentionsModule, kind_of, phone_pattern
from tests.test_companies import broker  # noqa: F401 - the account service fixture
from tests.test_modules_offline import FakeResponse, FakeSession, collect


# ---------------------------------------------------------------------------- the number itself
def test_a_london_landline():
    facts = describe("+44 20 7946 0000")
    assert facts["valid"] and facts["country_code"] == "GB" and facts["area"] == "London"
    assert facts["line_type"] == "landline" and facts["e164"] == "+442079460000"
    assert set(facts["written_as"]) >= {"+44 20 7946 0000", "020 7946 0000", "02079460000", "+442079460000"}
    assert "Europe/London" in facts["time_zones"]


def test_mobile_voip_and_reserved_numbers():
    us_mobile = describe("+1 650-253-0000")
    assert us_mobile["valid"] and us_mobile["country_code"] == "US"
    uk_voip = describe("+44 56 1234 5678")  # 056: UK VoIP
    assert uk_voip["line_type"] == "VoIP (internet phone)" and uk_voip["concealing_line"] is True
    drama = describe("+44 7700 900123")  # Ofcom's range for TV and film
    assert drama["valid"] is False and "line_type" not in drama
    assert describe("hello") is None and describe("+44 12") is None


async def test_the_module_only_enriches_and_contacts_nobody():
    session = FakeSession({})
    phone = Entity.create(EntityType.PHONE, "+44 7700 900123")
    entities, _ = await collect(PhoneReconModule(), phone, session)
    assert not entities and not session.requested
    assert phone.metadata["phone_valid"] is False and "TV and film" in phone.metadata["phone"]["note"]
    module = PhoneReconModule()
    assert module.enrichment and module.third_party_safe and not module.active


# ---------------------------------------------------------------------------- where it is published
def test_kinds_of_page():
    assert kind_of("https://www.tellows.co.uk/num/02079460000") == "nuisance report"
    assert kind_of("https://pastebin.com/abc") == "paste site"
    assert kind_of("https://m.facebook.com/someone") == "social media"
    assert kind_of("https://notfacebook.com/x") == "web page"
    assert kind_of("https://www.facebook.com/someone") == "social media"
    assert kind_of("https://www.gumtree.com/p/sofa/123") == "classifieds"
    assert kind_of("https://hope.test/contact") == "web page"


def test_the_number_is_found_however_it_is_written():
    pattern = phone_pattern("2079460000")
    for text in ("+44 20 7946 0000", "020 7946 0000", "02079460000", "(020) 7946-0000", "+44 (0)20 7946 0000"):
        assert pattern.search(text), text
    assert not pattern.search("020 7946 00001") and not pattern.search("020 7946 0001")


@pytest.fixture
def own_search_key(monkeypatch):
    monkeypatch.setenv("ARGUS_WEB_SEARCH_API_KEY", "own-search-key")
    get_settings.cache_clear()


RESULTS = {"web": {"results": [
    {"url": "https://www.tellows.co.uk/num/02079460000", "title": "02079460000 - scam? 34 ratings",
     "description": "People report <strong>020 7946 0000</strong> as a fake bank call."},
    {"url": "https://www.gumtree.com/p/van/1", "title": "Van for sale", "description": "Call +44 20 7946 0000 after 6pm"},
    {"url": "https://example.org/near-miss", "title": "Call 020 7946 0001", "description": "A different number"},
    {"url": "javascript:alert(1)", "title": "02079460000", "description": ""},
]}}  # fmt: skip


class SearchSession(FakeSession):
    def __init__(self, answer):
        super().__init__({r"api\.search\.brave\.com": answer})
        self.headers, self.params = [], []

    def get(self, url, **kwargs):
        self.headers.append(kwargs.get("headers") or {})
        self.params.append(kwargs.get("params") or {})
        return super().get(url, **kwargs)


async def test_mentions_are_searched_and_checked(own_search_key):
    session = SearchSession(FakeResponse(200, RESULTS))
    phone = Entity.create(EntityType.PHONE, "+442079460000")
    entities, relations = await collect(WebMentionsModule(), phone, session)
    assert session.headers[0]["X-Subscription-Token"] == "own-search-key"
    query = session.params[0]["q"]
    assert '"+44 20 7946 0000"' in query and '"020 7946 0000"' in query and " OR " in query and len(query) <= 160
    assert [e.value for e in entities] == [
        "https://www.tellows.co.uk/num/02079460000",
        "https://www.gumtree.com/p/van/1",
    ]
    assert (
        entities[0].metadata["mention_kind"] == "nuisance report" and "<strong>" not in entities[0].metadata["snippet"]
    )
    assert all(e.metadata["out_of_scope"] for e in entities)  # third-party pages: never scanned
    assert phone.metadata["web_mentions"] == {"searched": query, "results": 4, "confirmed": 2,
                                              "by_kind": {"nuisance report": 1, "classifieds": 1}}  # fmt: skip
    assert relations[0].label == "Mentioned on (nuisance report)"


async def test_emails_are_searched_exactly_and_invalid_numbers_cost_nothing(own_search_key):
    session = SearchSession(FakeResponse(200, {"web": {"results": [
        {"url": "https://forum.test/t/1", "title": "Contact", "description": "Mail Jane.Roe@Example.org for details"},
        {"url": "https://forum.test/t/2", "title": "Contact", "description": "Mail jane.roe@example.com"}]}}))  # fmt: skip
    email = Entity.create(EntityType.EMAIL, "jane.roe@example.org")
    entities, _ = await collect(WebMentionsModule(), email, session)
    assert session.params[0]["q"] == '"jane.roe@example.org"' and [e.value for e in entities] == [
        "https://forum.test/t/1"
    ]
    fake = SearchSession(FakeResponse(200, RESULTS))
    await collect(WebMentionsModule(), Entity.create(EntityType.PHONE, "+44 7700 900123"), fake)
    assert fake.requested == []  # an invented number is never searched


def test_web_search_is_a_fixed_paid_lookup(monkeypatch):
    url, query = connectors.build("web_search", "web", {"q": '"+44 20 7946 0000"'})
    assert url == "https://api.search.brave.com/res/v1/web/search" and query["count"] == "20"
    assert connectors.operation("web_search", "web").credits == 1
    with pytest.raises(connectors.ConnectError):
        connectors.build("web_search", "web", {"q": "x" * 200})
    monkeypatch.delenv("ARGUS_WEB_SEARCH_API_KEY", raising=False)
    monkeypatch.setenv("ARGUS_EDITION", "server")
    get_settings.cache_clear()
    assert WebMentionsModule.is_configured() is False  # no key, no account: not run


def test_the_phone_playbook_reports_line_type_and_mentions():
    g = IntelligenceGraph("p")
    voip = Entity.create(EntityType.PHONE, "+445612345678", metadata={
        "phone": describe("+44 56 1234 5678"), "phone_valid": True})  # fmt: skip
    fake = Entity.create(EntityType.PHONE, "+447700900123", depth=1, metadata={"phone_valid": False})
    report = Entity.create(EntityType.URL, "https://www.tellows.co.uk/num/05612345678", label="Scam? 34 ratings",
                           depth=1, metadata={"category": "mention", "mention_kind": "nuisance report",
                                              "snippet": "Fake bank call"})  # fmt: skip
    ad = Entity.create(EntityType.URL, "https://www.gumtree.com/p/van/1", label="Van", depth=1,
                       metadata={"category": "mention", "mention_kind": "classifieds"})  # fmt: skip
    for e in (voip, fake, report, ad):
        g.add_entity(e, is_seed=e.depth == 0)
    found = {h.title: h for h in playbooks.highlights(g)}
    assert found["+445612345678: VoIP (internet phone)"].level == "medium"
    assert found["+447700900123 is not a real number range"].level == "medium"
    assert found["Mentioned on a nuisance-call report site: Scam? 34 ratings"].level == "medium"
    assert found["Mentioned on a classifieds site: Van"].level == "info"
    assert playbooks.capture_urls(g, ("mentions",), "+445612345678", 5) == [
        "https://www.tellows.co.uk/num/05612345678",
        "https://www.gumtree.com/p/van/1",
    ]


def test_argus_connect_brokers_web_searches_for_credits(broker, monkeypatch):  # noqa: F811
    c, ch, licence = broker
    monkeypatch.setitem(connectors.BASES, "web_search", ch.url)
    monkeypatch.setattr(c.app.state.settings, "web_search_api_key",
                        type("K", (), {"get_secret_value": staticmethod(lambda: "operator-search-key")})())  # fmt: skip
    ask = lambda q: c.post("/api/connect/web_search", json={"licence": licence, "operation": "web", "params": {"q": q}})  # noqa: E731
    nothing = ask('"+44 20 7946 0000"')  # the stand-in has no search page: "not found", refunded
    assert nothing.status_code == 200 and nothing.json()["credits"]["charged"] == 0
    assert ask("x" * 200).status_code == 422  # refused before any credit is taken
    balance = c.post("/api/connect/balance", json={"licence": licence}).json()
    assert balance["credits"]["available"] == 50 and balance["prices"]["web_search"]["lookups"] == {"web": 1}
