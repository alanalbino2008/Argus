"""Lookalike domains: candidate generation, DNS verdicts, scope safety and attack paths."""

from __future__ import annotations

from typing import Any

import dns.asyncresolver
import dns.resolver
import pytest

from argus.core.engine import ArgusEngine
from argus.core.events import EventBus
from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, ScanConfig
from argus.intel.lookalikes import TECHNIQUE_ORDER, generate, split_domain
from argus.intel.paths import find_attack_paths
from argus.modules.base import BaseModule
from argus.modules.threat_intel.lookalike_domains import LookalikeDomainsModule, risk_score
from tests.test_modules_offline import CONFIG, FakeSession, rr


# ---------------------------------------------------------------------------- generation
def test_candidates_cover_the_techniques_attackers_use():
    names = {c.domain: c for c in generate("acme.com", limit=5000)}
    for expected, technique in [
        ("acme-login.com", "combosquat"), ("secure-acme.com", "combosquat"), ("acrne.com", "homoglyph"),
        ("acme.co", "tld"), ("acme.co.uk", "tld"), ("acm.com", "typo"), ("acmme.com", "typo"),
        ("came.com", "typo"), ("acne.com", "typo"), ("wwwacme.com", "doppelganger"), ("acme.net", "tld"),
    ]:  # fmt: skip
        assert names[expected].technique == technique, expected
    assert "acme.com" not in names
    idn = [c for c in names.values() if c.domain.startswith("xn--")]
    assert idn and all(c.domain.encode().decode("idna") == c.display for c in idn)
    assert any(c.display == "\u0430cme.com" for c in idn)  # Cyrillic a, looks identical
    assert all(c.domain.isascii() and len(c.domain.split(".")[0]) <= 63 for c in names.values())


def test_generation_is_bounded_ordered_and_deterministic():
    capped = generate("acme-corp.com", limit=50)
    assert len(capped) == 50 and capped == generate("acme-corp.com", limit=50)
    order = [TECHNIQUE_ORDER.index(c.technique) for c in generate("acme-corp.com")]
    assert order == sorted(order)  # most dangerous techniques first: a cap keeps them
    assert {c.technique for c in capped} == {"combosquat"}


def test_multi_part_suffixes_and_subdomains():
    assert split_domain("shop.acme.co.uk") == ("acme", "co.uk")
    assert split_domain("www.acme.com") == ("acme", "com")
    names = {c.domain for c in generate("acme.co.uk", limit=5000)}
    assert {"acme-login.co.uk", "acme.com", "acrne.co.uk"} <= names
    with pytest.raises(ValueError, match="not a domain"):
        split_domain("localhost")


# ---------------------------------------------------------------------------- the module (fake DNS)
WILDCARD_TLD = "xyz"


@pytest.fixture
def lookalike_dns(monkeypatch):
    """acme.com and a few registered lookalikes; every *.xyz name answers (a wildcard TLD)."""
    table: dict[tuple[str, str], list[Any]] = {
        ("acme.com", "A"): rr("A", "198.51.100.10"),
        ("acme.com", "NS"): rr("NS", "ns1.acme-dns.com."),
        # An impostor with mail: suspicious and dangerous
        ("acme-login.com", "A"): rr("A", "203.0.113.66"),
        ("acme-login.com", "NS"): rr("NS", "ns1.cheap-host.net."),
        ("acme-login.com", "MX"): rr("MX", "10 mail.acme-login.com."),
        # The company's own defensive registration (same address)
        ("acme.net", "A"): rr("A", "198.51.100.10"),
        ("acme.net", "NS"): rr("NS", "ns2.acme-dns.com."),
        # Parked by a speculator
        ("acrne.com", "NS"): rr("NS", "ns1.sedoparking.com."),
    }

    async def resolve(self, qname, rdtype="A", *args, **kwargs):
        name, rtype = str(qname).rstrip(".").lower(), str(rdtype)
        if name.endswith("." + WILDCARD_TLD):
            if rtype == "A":
                return rr("A", "192.0.2.1")
            raise dns.resolver.NoAnswer
        if (name, rtype) in table:
            return table[(name, rtype)]
        if any(n == name for n, _ in table):
            raise dns.resolver.NoAnswer
        raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    return table


async def run_module(seed_value="acme.com", depth=0):
    seed = Entity.create(EntityType.DOMAIN, seed_value, depth=depth)
    module = LookalikeDomainsModule()
    if not module.can_handle(seed):
        return seed, []
    items = [x async for x in module.run(seed, FakeSession({}), CONFIG)]
    return seed, [x for x in items if isinstance(x, Entity)]


async def test_registered_lookalikes_are_found_and_judged(lookalike_dns):
    seed, found = await run_module()
    verdicts = {e.value: e.metadata["lookalike"] for e in found}
    assert set(verdicts) == {"acme-login.com", "acme.net", "acrne.com"}  # acme.xyz: wildcard, ignored
    login = verdicts["acme-login.com"]
    assert login["verdict"] == "suspicious" and login["mx"] == ["mail.acme-login.com"] and login["sensitive_keyword"]
    assert login["risk"] >= 80
    assert verdicts["acme.net"]["verdict"] == "yours" and verdicts["acme.net"]["risk"] <= 10
    assert verdicts["acrne.com"]["verdict"] == "parked" and verdicts["acrne.com"]["technique"] == "homoglyph"
    assert all(e.metadata["out_of_scope"] for e in found)
    assert WILDCARD_TLD in seed.metadata["lookalikes_wildcard_tlds"]
    assert seed.metadata["lookalikes_registered"] == 3 and seed.metadata["lookalikes_checked"] > 200


async def test_only_the_seed_brand_is_checked(lookalike_dns):
    _, found = await run_module(depth=1)  # e.g. a mail provider's domain discovered during the scan
    assert found == []


def test_risk_scoring():
    assert risk_score("combosquat", True, True, True, "suspicious") > risk_score(
        "typo", False, False, True, "suspicious"
    )
    assert risk_score("homoglyph", False, True, True, "parked") <= 45
    assert risk_score("homoglyph", True, True, True, "yours") == 5


# ---------------------------------------------------------------------------- scope safety
class Spy(BaseModule):
    """Records every entity any module is asked to process."""

    name = "spy"
    supported_entity_types = [EntityType.DOMAIN]

    def __init__(self):
        self.seen: list[str] = []

    async def run(self, entity, session, config):
        self.seen.append(entity.value)
        return
        yield  # pragma: no cover


async def test_the_engine_never_investigates_a_lookalike(lookalike_dns):
    spy = Spy()
    config = ScanConfig(target="acme.com", target_type=EntityType.DOMAIN, max_depth=3)
    engine = ArgusEngine(config, bus=EventBus(), modules={m.name: m for m in (LookalikeDomainsModule(), spy)})
    graph = await engine.start()
    lookalikes = [e for e in graph.get_all_entities() if e.metadata.get("lookalike")]
    assert len(lookalikes) == 3
    assert spy.seen == ["acme.com"]  # recorded in the graph, but no module ever ran against a third party


# ---------------------------------------------------------------------------- attack paths
def _graph_with(*facts: tuple[str, dict[str, Any]]) -> IntelligenceGraph:
    graph = IntelligenceGraph("inv_test")
    seed = Entity.create(EntityType.DOMAIN, "acme.com", depth=0)
    graph.add_entity(seed, is_seed=True)
    for value, fact in facts:
        base = {"of": "acme.com", "technique": "combosquat", "detail": "brand + 'login'", "display": value,
                "verdict": "suspicious", "mx": [], "ns": ["ns1.cheap-host.net"], "ips": ["203.0.113.66"],
                "sensitive_keyword": False, "risk": 30}  # fmt: skip
        graph.add_entity(Entity.create(EntityType.DOMAIN, value, metadata={"lookalike": {**base, **fact}}, depth=1))
    return graph


def test_dangerous_lookalikes_become_attack_paths():
    graph = _graph_with(
        ("acme-login.com", {"mx": ["mail.acme-login.com"], "sensitive_keyword": True, "risk": 87}),
        ("acme.net", {"verdict": "yours", "risk": 5, "mx": ["mx.acme.com"]}),
        ("acmme.com", {"technique": "typo", "risk": 35}),
        ("acrne.com", {"verdict": "parked", "risk": 30}),
    )
    paths = find_attack_paths(graph)["paths"]
    rules = [p["rule"] for p in paths]
    assert rules.count("lookalike_domain") == 1 and rules.count("lookalike_domain_watchlist") == 1
    main = next(p for p in paths if p["rule"] == "lookalike_domain")
    assert main["title"] == "Lookalike domain acme-login.com could impersonate acme.com (it can send email)"
    assert main["severity"] in ("high", "critical")
    assert [t["id"] for t in main["techniques"]] == ["T1583.001", "T1566"]
    assert "abuse" in main["remediation"][0] and "UDRP" in main["remediation"][0]
    watch = next(p for p in paths if p["rule"] == "lookalike_domain_watchlist")
    assert watch["title"].startswith("2 more registered lookalike") and "acme.net" not in watch["narrative"]
    assert not any("acme.net" in p["title"] for p in paths)  # your own registrations are never findings
