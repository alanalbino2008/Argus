"""Optional API-key modules: VirusTotal, Have I Been Pwned, Shodan host - and secret handling."""

import pytest

from argus.core.engine import ArgusEngine
from argus.core.events import EventBus
from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, ScanConfig
from argus.core.runctx import ModuleRunReport
from argus.core.settings import get_settings
from argus.modules import get_default_modules, get_module_catalog
from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer
from argus.modules.base import BaseModule
from argus.modules.threat_intel.hibp import HibpModule
from argus.modules.threat_intel.shodan_host import ShodanHostModule
from argus.modules.threat_intel.virustotal import VirusTotalModule
from argus.security.secrets import REDACTED, register_secret
from tests.test_modules_offline import FakeResponse, FakeSession, collect

VT_KEY, HIBP_KEY, SHODAN_KEY = "vt-test-key-1234567890", "hibp-test-key-1234567890", "shodan-test-key-1234567890"


class RecordingSession(FakeSession):
    def __init__(self, routes):
        super().__init__(routes)
        self.kwargs: list[dict] = []

    def get(self, url, **kwargs):
        self.kwargs.append(kwargs)
        return super().get(url, **kwargs)


@pytest.fixture
def keys(monkeypatch):
    monkeypatch.setenv("ARGUS_VIRUSTOTAL_API_KEY", VT_KEY)
    monkeypatch.setenv("ARGUS_HIBP_API_KEY", HIBP_KEY)
    monkeypatch.setenv("ARGUS_SHODAN_API_KEY", SHODAN_KEY)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def no_keys(monkeypatch):
    for name in ("VIRUSTOTAL", "HIBP", "SHODAN"):
        monkeypatch.delenv(f"ARGUS_{name}_API_KEY", raising=False)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


# ------------------------------------------------------------------- enablement
def test_api_key_modules_are_off_without_keys(no_keys):
    loaded = set(get_default_modules())
    assert not {"virustotal", "hibp", "shodan_host"} & loaded
    assert {"virustotal", "hibp", "shodan_host"} <= set(get_module_catalog())


def test_api_key_modules_load_with_keys(keys):
    assert {"virustotal", "hibp", "shodan_host"} <= set(get_default_modules())


# ------------------------------------------------------------------- VirusTotal
async def test_virustotal_reputation_and_risk_flag(keys):
    session = RecordingSession(
        {
            r"virustotal\.com/api/v3/domains/evil\.example": FakeResponse(
                body={
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {"malicious": 7, "suspicious": 1, "harmless": 50, "undetected": 20},
                            "reputation": -42,
                            "categories": {"vendorA": "phishing", "vendorB": "phishing"},
                        }
                    }
                }
            )
        }
    )
    domain = Entity.create(EntityType.DOMAIN, "evil.example")
    await collect(VirusTotalModule(), domain, session)
    assert session.kwargs[0]["headers"]["x-apikey"] == VT_KEY  # header, never the URL
    assert VT_KEY not in session.requested[0]
    assert domain.metadata["virustotal"]["malicious"] == 7
    assert domain.metadata["virustotal"]["categories"] == ["phishing"]

    graph = IntelligenceGraph("t")
    graph.add_entity(domain, is_seed=True)
    flags = GraphIntelligenceAnalyzer.analyze(graph)["risk_flags"]
    assert "evil.example flagged malicious by 7 VirusTotal engine(s)" in flags


# ------------------------------------------------------------------------- HIBP
async def test_hibp_breaches_become_entities(keys):
    session = RecordingSession(
        {
            r"haveibeenpwned\.com/api/v3/breachedaccount/jane%40example\.com": FakeResponse(
                body=[
                    {
                        "Name": "Adobe",
                        "Title": "Adobe",
                        "BreachDate": "2013-10-04",
                        "Domain": "adobe.com",
                        "PwnCount": 152445165,
                        "DataClasses": ["Email addresses", "Passwords"],
                        "IsVerified": True,
                    },
                    {
                        "Name": "LinkedIn",
                        "Title": "LinkedIn",
                        "BreachDate": "2012-05-05",
                        "DataClasses": ["Passwords"],
                        "IsVerified": True,
                    },
                ]
            )
        }
    )
    email = Entity.create(EntityType.EMAIL, "Jane@Example.com")
    entities, relations = await collect(HibpModule(), email, session)
    assert sorted(e.value for e in entities) == ["Adobe", "LinkedIn"]
    assert all(e.type == EntityType.BREACH for e in entities)
    assert len(relations) == 2 and all(r.label == "Exposed in breach" for r in relations)
    assert email.metadata["breach_count"] == 2
    assert session.kwargs[0]["headers"]["hibp-api-key"] == HIBP_KEY


async def test_hibp_not_pwned_is_a_clean_answer(keys):
    email = Entity.create(EntityType.EMAIL, "clean@example.com")
    entities, _ = await collect(HibpModule(), email, RecordingSession({}))  # FakeSession 404s by default
    assert entities == [] and email.metadata["breach_count"] == 0


# ----------------------------------------------------------------- Shodan host
async def test_shodan_host_services_versions_and_cves(keys):
    session = RecordingSession(
        {
            r"api\.shodan\.io/shodan/host/8\.8\.8\.8": FakeResponse(
                body={
                    "org": "Google LLC",
                    "os": None,
                    "hostnames": ["dns.google"],
                    "vulns": ["CVE-2021-0001"],
                    "data": [
                        {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18.0"},
                        {"port": 53, "transport": "udp"},
                    ],
                }
            )
        }
    )
    ip = Entity.create(EntityType.IP_ADDRESS, "8.8.8.8")
    entities, _ = await collect(ShodanHostModule(), ip, session)
    by_type = {}
    for e in entities:
        by_type.setdefault(e.type, []).append(e.value)
    assert sorted(by_type[EntityType.PORT]) == ["8.8.8.8:443", "8.8.8.8:53"]
    assert by_type[EntityType.TECHNOLOGY] == ["nginx 1.18.0"]
    assert by_type[EntityType.VULNERABILITY] == ["CVE-2021-0001"]
    assert ip.metadata["shodan_org"] == "Google LLC"


async def test_shodan_host_never_sends_private_ips(keys):
    session = RecordingSession({})
    await collect(ShodanHostModule(), Entity.create(EntityType.IP_ADDRESS, "192.168.1.10"), session)
    assert session.requested == []


# ------------------------------------------------------------ secret handling
def test_secrets_are_redacted_from_recorded_errors():
    register_secret("super-secret-api-key-xyz")
    report = ModuleRunReport("m", "e")
    report.record_error(
        "api.example.com", ValueError("GET https://api.example.com/x?key=super-secret-api-key-xyz failed")
    )
    assert "super-secret-api-key-xyz" not in report.errors[0] and REDACTED in report.errors[0]


async def test_module_crash_containing_a_key_is_redacted(keys):
    class LeakyModule(BaseModule):
        name = "leaky"
        supported_entity_types = [EntityType.DOMAIN]
        requires_settings = ("shodan_api_key",)

        async def run(self, entity, session, config):
            key = self.secret("shodan_api_key")
            raise RuntimeError(f"InvalidURL https://api.shodan.io/x?key={key}")
            yield  # pragma: no cover

    engine = ArgusEngine(
        ScanConfig(target="example.com", target_type=EntityType.DOMAIN),
        bus=EventBus(),
        modules={"leaky": LeakyModule()},
    )
    await engine.start()
    text = " ".join(engine.investigation.errors)
    assert SHODAN_KEY not in text and REDACTED in text


async def test_engine_applies_per_service_rate_limits(keys):
    class OfflineVirusTotal(VirusTotalModule):  # same quota declaration, no network call
        async def run(self, entity, session, config):
            return
            yield  # pragma: no cover

    engine = ArgusEngine(
        ScanConfig(target="example.com", target_type=EntityType.DOMAIN, max_depth=0),
        bus=EventBus(),
        modules={"virustotal": OfflineVirusTotal()},
    )
    await engine.start()
    assert engine.http.limiter.host_intervals["www.virustotal.com"] == 15.0


def test_api_reports_configuration_and_rejects_unconfigured_modules(client, no_keys):
    modules = {m["name"]: m for m in client.get("/api/modules").json()}
    assert modules["virustotal"]["configured"] is False
    assert modules["virustotal"]["requires"] == ["virustotal_api_key"]
    r = client.post(
        "/api/scan",
        json={
            "target": "example.com",
            "purpose": "Authorised test",
            "authorized": True,
            "enabled_modules": ["virustotal"],
        },
    )
    assert r.status_code == 422 and "API key" in r.json()["detail"]
