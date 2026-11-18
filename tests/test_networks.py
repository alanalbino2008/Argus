"""Network ranges: who owns an address block, a network's ranges, and a company's own networks."""

from __future__ import annotations

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, RelationType
from argus.intel import playbooks
from argus.modules.infrastructure.network_ranges import NetworkRangesModule, address_count, is_provider, rdap_network
from tests.test_modules_offline import FakeResponse, FakeSession, collect

RDAP_ANSWER = {
    "handle": "NET-198-51-100-0-1", "name": "ACME-NET", "country": "GB", "port43": "whois.ripe.net",
    "cidr0_cidrs": [{"v4prefix": "198.51.100.0", "length": 24}],
    "entities": [
        {"roles": ["registrant"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "Acme Holdings Ltd"]]]},
        {"roles": ["technical"], "entities": [
            {"roles": ["abuse"], "vcardArray": ["vcard", [["email", {}, "text", "abuse@acme.example"]]]}]},
    ],
}  # fmt: skip


def test_an_rdap_answer_is_read():
    assert rdap_network(RDAP_ANSWER) == {
        "block": "198.51.100.0/24", "name": "ACME-NET", "handle": "NET-198-51-100-0-1",
        "registered_to": "Acme Holdings Ltd", "country": "GB", "abuse_contact": "abuse@acme.example", "registry": "RIPE.NET",
    }  # fmt: skip
    ranged = rdap_network({"startAddress": "203.0.113.0", "endAddress": "203.0.113.127"})
    assert ranged["block"] == "203.0.113.0/25"


def test_providers_and_address_counts():
    assert is_provider("AMAZON-02 - Amazon.com, Inc.") and is_provider(None, "CLOUDFLARENET")
    assert not is_provider("Acme Holdings Ltd", "ACME-NET")
    assert address_count(["198.51.100.0/24", "203.0.113.0/25", "2001:db8::/32", "nonsense"]) == 384


async def test_an_ip_address_gets_its_block_owner_and_network():
    session = FakeSession({
        r"rdap\.org/ip/8\.8\.4\.4$": FakeResponse(200, RDAP_ANSWER),
        r"prefix-overview/data\.json\?resource=8\.8\.4\.4$": FakeResponse(200, {"data": {
            "resource": "198.51.100.0/24", "asns": [{"asn": 64500, "holder": "ACME-NET - Acme Holdings Ltd"}]}}),
    })  # fmt: skip
    ip = Entity.create(EntityType.IP_ADDRESS, "8.8.4.4", depth=1)
    entities, relations = await collect(NetworkRangesModule(), ip, session)
    assert ip.metadata["network"]["registered_to"] == "Acme Holdings Ltd"
    assert (
        ip.metadata["network"]["announced_as"] == "198.51.100.0/24"
        and ip.metadata["network"]["shared_provider"] is False
    )
    assert [e.value for e in entities] == ["AS64500"] and entities[0].depth == 2
    assert relations[0].type == RelationType.HOSTED_ON and "AS64500" in relations[0].label
    assert all("acme" not in u for u in session.requested)  # only the registries are asked


async def test_private_addresses_are_never_looked_up():
    session = FakeSession({})
    await collect(NetworkRangesModule(), Entity.create(EntityType.IP_ADDRESS, "10.1.2.3"), session)
    assert session.requested == []


async def test_a_company_network_lists_its_ranges_but_a_provider_does_not():
    session = FakeSession({
        r"as-overview/data\.json\?resource=AS64500$": FakeResponse(200, {"data": {"holder": "ACME-NET - Acme Holdings Ltd"}}),
        r"announced-prefixes/data\.json\?resource=AS64500$": FakeResponse(200, {"data": {"prefixes": [
            {"prefix": "203.0.113.0/25"}, {"prefix": "198.51.100.0/24"}, {"prefix": "2001:db8::/32"}]}}),
        r"as-overview/data\.json\?resource=AS16509$": FakeResponse(200, {"data": {"holder": "AMAZON-02 - Amazon.com, Inc."}}),
    })  # fmt: skip
    own = Entity.create(EntityType.ASN, "AS64500", depth=1)
    await collect(NetworkRangesModule(), own, session)
    r = own.metadata["network_ranges"]
    assert r["ranges_v4"] == ["198.51.100.0/24", "203.0.113.0/25"] and r["ranges_v6"] == ["2001:db8::/32"]
    assert r["range_count"] == 3 and r["addresses_v4"] == 384 and r["shared_provider"] is False
    amazon = Entity.create(EntityType.ASN, "AS16509", depth=1)
    await collect(NetworkRangesModule(), amazon, session)
    assert (
        amazon.metadata["network_ranges"]["shared_provider"] is True
        and "ranges_v4" not in amazon.metadata["network_ranges"]
    )
    assert not any("announced-prefixes/data.json?resource=AS16509" in u for u in session.requested)


async def test_a_company_name_finds_networks_registered_to_it():
    session = FakeSession({r"searchcomplete/data\.json\?resource=Acme%20Holdings%20Ltd$": FakeResponse(200, {"data": {
        "categories": [{"category": "ASNs", "suggestions": [
            {"value": "AS64500", "description": "ACME-NET - Acme Holdings Ltd"},
            {"value": "AS64501", "description": "ACMEX - Acmex Trading Ltd"},  # a different company
            {"value": "AS16509", "description": "AMAZON-02 - Amazon.com, Inc."}]},
            {"category": "Prefixes", "suggestions": [{"value": "198.51.100.0/24"}]}]}})})  # fmt: skip
    company = Entity.create(EntityType.ORGANIZATION, "Acme Holdings Ltd")
    entities, relations = await collect(NetworkRangesModule(), company, session)
    assert [e.value for e in entities] == ["AS64500"] and entities[0].metadata["matched_by"] == "registry name"
    assert entities[0].confidence < 1 and relations[0].type == RelationType.OPERATES
    module = NetworkRangesModule()
    assert not module.can_handle(Entity.create(EntityType.ORGANIZATION, "Some Supplier Ltd", depth=1))
    assert module.third_party_safe and not module.active


def test_the_playbooks_report_blocks_and_networks():
    g = IntelligenceGraph("n")
    shared = Entity.create(EntityType.IP_ADDRESS, "104.16.1.1", metadata={"network": {
        "registered_to": "Cloudflare, Inc.", "shared_provider": True}})  # fmt: skip
    own_ip = Entity.create(EntityType.IP_ADDRESS, "198.51.100.7", depth=1, metadata={"network": {
        "block": "198.51.100.0/24", "registered_to": "Acme Holdings Ltd", "registry": "RIPE.NET", "country": "GB",
        "shared_provider": False}})  # fmt: skip
    asn = Entity.create(EntityType.ASN, "AS64500", depth=1, metadata={"matched_by": "registry name", "network_ranges": {
        "holder": "ACME-NET", "range_count": 3, "addresses_v4": 384, "shared_provider": False}})  # fmt: skip
    for e in (shared, own_ip, asn):
        g.add_entity(e, is_seed=e.depth == 0)
    titles = {h.title: h for h in playbooks.highlights(g)}
    assert "104.16.1.1: shared hosting (Cloudflare, Inc.)" in titles
    assert "198.51.100.7: in 198.51.100.0/24 registered to Acme Holdings Ltd" in titles
    net = titles["Network AS64500 (ACME-NET): 3 address ranges, 384 IPv4 addresses"]
    assert "confirm it is the same company" in net.detail
