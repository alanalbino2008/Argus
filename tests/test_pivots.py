"""Infrastructure pivoting: evidence, attribution, sources (faked), scope and impostor campaigns."""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.resolver
import pytest

from argus.core.engine import ArgusEngine
from argus.core.events import EventBus
from argus.core.models import Entity, EntityType, ScanConfig
from argus.intel.paths import find_attack_paths
from argus.intel.pivots import Evidence, Related, combine, domains_in, extract_trackers, looks_like_brand
from argus.modules.base import BaseModule
from argus.modules.threat_intel.infrastructure_pivot import InfrastructurePivotModule
from tests.test_modules_offline import CONFIG, FakeResponse, FakeSession, rr

# A real (expired) self-signed certificate for O="Acme Corporation Ltd", generated for this test.
PEM: str = ""


@pytest.fixture(scope="module", autouse=True)
def _certificate():
    """Build an OV-style certificate on the fly (subject O=Acme Corporation Ltd)."""
    global PEM
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "acme.com"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Acme Corporation Ltd")])  # fmt: skip
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )  # fmt: skip
    PEM = cert.public_bytes(serialization.Encoding.PEM).decode()


# ---------------------------------------------------------------------------- pure logic
def test_trackers_are_extracted_by_account():
    html = (
        "ga('create','UA-1234567-2'); ga('create','UA-1234567-9'); gtag('config','G-AB12CD34EF');"
        " 'GTM-K9X2P7Q' data-ad-client='ca-pub-1234567890123456' fbq('init', '123456789012345')"
    )
    assert extract_trackers(html) == {
        "UA-1234567": "Google Analytics",  # one account, two properties
        "G-AB12CD34EF": "Google Analytics 4",
        "GTM-K9X2P7Q": "Google Tag Manager",
        "ca-pub-1234567890123456": "Google AdSense",
        "123456789012345": "Meta pixel",
    }


def test_evidence_combines_with_noisy_or_and_counts_each_kind_once():
    r = Related("acme.io", [Evidence("analytics", "UA-1", ""), Evidence("shared_ip", "1.2.3.4", "")])
    assert r.confidence == pytest.approx(1 - 0.1 * 0.6) and r.attribution == "likely the same organisation"
    same_kind = Related("x.com", [Evidence("shared_ip", "1.1.1.1", ""), Evidence("shared_ip", "2.2.2.2", "")])
    assert same_kind.confidence == 0.4  # two co-hosting coincidences are not two proofs
    kept = combine([("x.com", Evidence("shared_ip", "1.1.1.1", "")), ("y.com", Evidence("certificate_org", "A", "")),
                    ("acme.com", Evidence("analytics", "UA-1", ""))], exclude={"acme.com"})  # fmt: skip
    assert [k.domain for k in kept] == ["y.com"]  # IP alone is too weak; the target itself excluded


def test_helpers():
    assert domains_in("acme.com\nShop.Acme.io,UA-1\nerror: API count exceeded") == ["acme.com", "shop.acme.io"]
    assert looks_like_brand("acme-secure-pay", "acme") and looks_like_brand("acne", "acme")
    assert looks_like_brand("acrne-sso", "acme") and looks_like_brand("acm3-portal", "acme")  # look-alikes + keyword
    assert not looks_like_brand("bakery", "acme") and not looks_like_brand("ac", "acme")
    assert not looks_like_brand("flowers", "acme") and not looks_like_brand("academy", "acme")


# ---------------------------------------------------------------------------- the module, faked sources
HTML = "<script>gtag('config','G-AB12CD34EF')</script>"


def routes(**overrides: Any) -> dict[str, FakeResponse]:
    base = {
        r"archive\.org/wayback/available": FakeResponse(
            200,
            {
                "archived_snapshots": {
                    "closest": {"available": True, "timestamp": "20261101000000", "url": "http://acme.com/"}
                }
            },
        ),
        r"web\.archive\.org/web/20261101000000id_/": FakeResponse(200, HTML),
        r"analyticslookup/\?q=G-AB12CD34EF": FakeResponse(200, "acme.com\nacme-careers.com\nwww.acme-labs.io"),
        r"crt\.sh/\?q=acme\.com&output=json": FakeResponse(
            200,
            [
                {"id": 11, "issuer_name": "C=US, O=Let's Encrypt, CN=R3", "not_before": "2026-10-01"},
                {"id": 22, "issuer_name": "C=GB, O=Sectigo Limited, CN=Sectigo RSA OV", "not_before": "2026-09-01"},
            ],
        ),
        r"crt\.sh/\?d=22": FakeResponse(200, PEM),
        r"crt\.sh/\?O=": FakeResponse(200, [{"name_value": "acme-labs.io\n*.acme-holdings.co.uk"}]),
        r"findshareddns/\?q=ns1\.acme\.com": FakeResponse(200, "acme.com\nacme-holdings.co.uk\nacme-careers.com"),
        r"reverseiplookup/\?q=198\.51\.100\.10": FakeResponse(200, "acme.com\nsmall-site.net\nacme-careers.com"),
        r"reverseiplookup/\?q=203\.0\.113\.66": FakeResponse(
            200, "acme-login.com\nacme-payroll.com\nflowers.net\nacrne-sso.com"
        ),
    }
    return {**base, **overrides}


@pytest.fixture
def pivot_dns(monkeypatch):
    table = {
        ("acme.com", "A"): rr("A", "198.51.100.10"),
        ("acme.com", "NS"): rr("NS", "ns1.acme.com.", "ns2.cloudflare.com."),
        ("acme-payroll.com", "MX"): rr("MX", "10 mx.acme-payroll.com."),
    }

    async def resolve(self, qname, rdtype="A", *args, **kwargs):
        key = (str(qname).rstrip(".").lower(), str(rdtype))
        if key in table:
            return table[key]
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)


async def collect(entity: Entity, session: FakeSession):
    items = [x async for x in InfrastructurePivotModule().run(entity, session, CONFIG)]
    return [x for x in items if isinstance(x, Entity)], [x for x in items if not isinstance(x, Entity)]


async def test_related_domains_are_attributed_with_evidence(pivot_dns):
    seed = Entity.create(EntityType.DOMAIN, "acme.com", depth=0)
    session = FakeSession(routes())
    entities, relations = await collect(seed, session)
    related = {e.value: e.metadata["pivot"] for e in entities if e.metadata.get("pivot")}
    assert set(related) == {"acme-careers.com", "acme-labs.io", "acme-holdings.co.uk"}  # small-site.net: IP only
    careers = related["acme-careers.com"]
    assert {e["kind"] for e in careers["evidence"]} == {"analytics", "own_nameserver", "shared_ip_small"}
    assert careers["confidence"] > 0.95 and careers["attribution"] == "likely the same organisation"
    assert {e["kind"] for e in related["acme-labs.io"]["evidence"]} == {"analytics", "certificate_org"}
    assert related["acme-holdings.co.uk"]["evidence"][0]["detail"] == "certificate issued to “Acme Corporation Ltd”"
    assert all(e.metadata["out_of_scope"] for e in entities)  # discovered, not authorised
    hubs = {e.value for e in entities if e.metadata.get("pivot_hub")}
    assert {"G-AB12CD34EF", "Acme Corporation Ltd", "ns1.acme.com", "198.51.100.10"} <= hubs
    assert len(relations) >= len(related) + len(hubs)
    assert seed.metadata["pivot_summary"]["certificate_org"] == "Acme Corporation Ltd"
    assert not any("cloudflare" in url for url in session.requested)  # generic name servers are not pivoted on
    # Passive: every request goes to a public database (the homepage comes from the Internet Archive).
    assert {urlsplit(u).hostname for u in session.requested} <= {
        "archive.org",
        "web.archive.org",
        "crt.sh",
        "api.hackertarget.com",
    }


async def test_shared_hosting_is_not_evidence(pivot_dns):
    crowded = "\n".join(f"site{i}.com" for i in range(40)) + "\nacme-careers.com"
    session = FakeSession(routes(**{r"reverseiplookup/\?q=198\.51\.100\.10": FakeResponse(200, crowded),
                                   r"analyticslookup/\?q=G-AB12CD34EF": FakeResponse(200, "API count exceeded")}))  # fmt: skip
    entities, _ = await collect(Entity.create(EntityType.DOMAIN, "acme.com", depth=0), session)
    kinds = {e["kind"] for x in entities if x.metadata.get("pivot") for e in x.metadata["pivot"]["evidence"]}
    assert "shared_ip" not in kinds and "shared_ip_small" not in kinds and "analytics" not in kinds


async def test_api_key_is_sent_when_configured(pivot_dns, monkeypatch):
    monkeypatch.setenv("ARGUS_HACKERTARGET_API_KEY", "ht-secret-key")
    from argus.core.settings import get_settings

    get_settings.cache_clear()
    session = FakeSession(routes())
    await collect(Entity.create(EntityType.DOMAIN, "acme.com", depth=0), session)
    assert any("apikey=ht-secret-key" in u for u in session.requested if "hackertarget" in u)
    get_settings.cache_clear()


def _impostor(**facts: Any) -> Entity:
    lookalike = {"of": "acme.com", "technique": "combosquat", "detail": "brand + 'login'", "display": "acme-login.com",
                 "verdict": "suspicious", "mx": ["mail.acme-login.com"], "ns": [], "ips": ["203.0.113.66"],
                 "sensitive_keyword": True, "risk": 87, **facts}  # fmt: skip
    return Entity.create(
        EntityType.DOMAIN, "acme-login.com", depth=1, metadata={"lookalike": lookalike, "out_of_scope": True}
    )


async def test_impostor_clusters_are_mapped_without_contacting_the_impostor(pivot_dns):
    impostor = _impostor()
    assert InfrastructurePivotModule().can_handle(impostor)
    session = FakeSession(routes())
    entities, _ = await collect(impostor, session)
    siblings = {e.value: e.metadata["lookalike"] for e in entities}
    assert set(siblings) == {"acme-payroll.com", "acrne-sso.com"}  # flowers.net does not imitate the brand
    assert (
        siblings["acme-payroll.com"]["mx"] == ["mx.acme-payroll.com"]
        and siblings["acme-payroll.com"]["cluster_of"] == "acme-login.com"
    )
    assert impostor.metadata["lookalike"]["cluster_size"] == 2
    assert {urlsplit(u).hostname for u in session.requested} == {"api.hackertarget.com"}  # only databases *about* it


def test_only_suspicious_third_parties_are_examined():
    module = InfrastructurePivotModule()
    assert not module.can_handle(_impostor(verdict="parked"))
    assert not module.can_handle(Entity.create(EntityType.DOMAIN, "acme-careers.com", depth=1,
                                               metadata={"pivot": {}, "out_of_scope": True}))  # fmt: skip
    assert not module.can_handle(Entity.create(EntityType.DOMAIN, "cdn.acme.com", depth=1))


# ---------------------------------------------------------------------------- engine scope
class Spy(BaseModule):
    name = "spy"
    supported_entity_types = [EntityType.DOMAIN]

    def __init__(self):
        self.seen: list[str] = []

    async def run(self, entity, session, config):
        self.seen.append(entity.value)
        return
        yield  # pragma: no cover


class Seeder(BaseModule):
    """Emits one impostor and one related domain from the seed."""

    name = "seeder"
    supported_entity_types = [EntityType.DOMAIN]

    def can_handle(self, entity):
        return entity.depth == 0

    async def run(self, entity, session, config):
        yield _impostor()
        yield Entity.create(
            EntityType.DOMAIN, "acme-careers.com", depth=1, metadata={"pivot": {}, "out_of_scope": True}
        )


class SafeSpy(Spy):
    name = "safe_spy"
    third_party_safe = True


async def test_only_third_party_safe_modules_see_out_of_scope_entities():
    spy, safe = Spy(), SafeSpy()
    config = ScanConfig(target="acme.com", target_type=EntityType.DOMAIN, max_depth=3)
    engine = ArgusEngine(config, bus=EventBus(), modules={m.name: m for m in (Seeder(), spy, safe)})
    await engine.start()
    assert spy.seen == ["acme.com"]
    assert sorted(safe.seen) == ["acme-careers.com", "acme-login.com", "acme.com"]


# ---------------------------------------------------------------------------- attack path
def test_impostor_campaign_becomes_one_attack_path():
    from argus.core.graph import IntelligenceGraph
    from argus.core.models import Relation, RelationType

    graph = IntelligenceGraph("inv")
    seed = Entity.create(EntityType.DOMAIN, "acme.com", depth=0)
    graph.add_entity(seed, is_seed=True)
    hub = _impostor(cluster_size=2)
    graph.add_entity(hub)
    graph.add_relation(Relation.create(hub.id, seed.id, RelationType.ASSOCIATED_WITH))
    for name in ("acme-payroll.com", "acrne-sso.com"):
        s = Entity.create(EntityType.DOMAIN, name, depth=2, metadata={"out_of_scope": True, "lookalike": {
            "of": "acme.com", "technique": "co-hosted", "detail": "on the same server as acme-login.com",
            "display": name, "verdict": "suspicious", "mx": [], "ns": [], "ips": ["203.0.113.66"],
            "sensitive_keyword": False, "risk": 37, "cluster_of": "acme-login.com"}})  # fmt: skip
        graph.add_entity(s)
        graph.add_relation(Relation.create(s.id, hub.id, RelationType.ASSOCIATED_WITH))
    paths = find_attack_paths(graph)["paths"]
    [campaign] = [p for p in paths if p["rule"] == "impostor_campaign"]
    assert campaign["title"] == "Impostor infrastructure: the server behind acme-login.com hosts 2 more lookalike(s)"
    assert [t["id"] for t in campaign["techniques"]] == ["T1583.001", "T1583.003", "T1566"]
    assert "whole cluster" in campaign["remediation"][0]
