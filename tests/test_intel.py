"""ATT&CK mapping, Navigator layer and STIX 2.1 export."""

import json

import pytest
import stix2

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Investigation, Relation, RelationType, ScanConfig
from argus.intel.attack import ENTITY_TECHNIQUES, TECHNIQUES, map_investigation, to_navigator_layer
from argus.intel.stix import build_bundle
from argus.modules import get_default_modules


def sample_graph():
    g = IntelligenceGraph("inv_test")
    seed = Entity.create(EntityType.DOMAIN, "example.com", depth=0)
    g.add_entity(seed, is_seed=True)
    found = [
        Entity.create(EntityType.SUBDOMAIN, "mail.example.com", depth=1),
        Entity.create(EntityType.IP_ADDRESS, "93.184.216.34", depth=1),
        Entity.create(EntityType.EMAIL, "ceo@example.com", depth=1),
        Entity.create(EntityType.PERSON, "Jane Doe", depth=2),
        Entity.create(EntityType.ORGANIZATION, "Example Registrar Inc", depth=1),
        Entity.create(EntityType.ASN, "AS15133", label="AS15133 Edgecast", depth=2, metadata={"as_name": "EDGECAST"}),
        Entity.create(EntityType.VULNERABILITY, "CVE-2023-44487", depth=2),
        Entity.create(EntityType.PORT, "93.184.216.34:443", depth=2),
        Entity.create(EntityType.TECHNOLOGY, "nginx", depth=1),
        Entity.create(
            EntityType.CERTIFICATE,
            "TLS-Cert: ab12",
            depth=1,
            metadata={
                "sha256_fingerprint": "ab" * 32,
                "serial": "a1b2",
                "issuer": "Let's Encrypt",
                "subject_cn": "example.com",
                "valid_from": "2026-01-01T00:00:00+00:00",
                "valid_to": "2026-04-01T00:00:00+00:00",
            },
        ),
        Entity.create(EntityType.SOCIAL_PROFILE, "https://github.com/janedoe", depth=2),
        Entity.create(EntityType.PHONE, "+44 20 7946 0958", depth=1),  # no STIX equivalent
    ]
    for e in found:
        g.add_entity(e)
    g.add_relation(Relation.create(seed.id, found[1].id, RelationType.RESOLVES_TO))
    g.add_relation(Relation.create(found[0].id, seed.id, RelationType.SUBDOMAIN_OF))
    g.add_relation(Relation.create(found[1].id, found[6].id, RelationType.EXPOSES))
    return g


def sample_investigation():
    return Investigation(
        id="inv_test", name="t", config=ScanConfig(target="example.com", target_type=EntityType.DOMAIN)
    )


# ----------------------------------------------------------------------------- ATT&CK
def test_every_declared_technique_exists():
    declared = {t for ts in ENTITY_TECHNIQUES.values() for t in ts}
    declared |= {t for m in get_default_modules().values() for t in m.attack_techniques}
    assert declared <= set(TECHNIQUES), declared - set(TECHNIQUES)
    assert all(t.parent in TECHNIQUES for t in TECHNIQUES.values())  # every sub-technique has its parent


def test_every_module_declares_techniques_and_active_flag():
    modules = get_default_modules()
    assert all(m.attack_techniques for m in modules.values())
    active = {n for n, m in modules.items() if m.active}
    # Only these touch the target's own systems (or guess its cloud storage); passive-only scans skip them.
    assert active == {"tls_analyzer", "http_fingerprint", "web_recon", "cloud_storage"}


def test_mapping_classifies_findings_but_not_the_seed():
    mapping = map_investigation(sample_graph(), get_default_modules())
    by_id = {t["id"]: t for t in mapping["techniques"]}
    assert by_id["T1589.002"]["examples"] == ["ceo@example.com"]
    assert by_id["T1596.005"]["count"] == 2  # open port + CVE from scan databases
    assert "T1590.001" not in by_id  # the seed domain is the target, not a finding
    assert by_id["T1589.002"]["url"] == "https://attack.mitre.org/techniques/T1589/002/"
    assert {e["module"] for e in mapping["emulation"]} == set(get_default_modules())


def test_navigator_layer_rolls_up_sub_techniques():
    layer = to_navigator_layer(map_investigation(sample_graph()), "Argus: example.com")
    assert layer["versions"]["layer"] == "4.5" and layer["domain"] == "enterprise-attack"
    scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
    # parent = its own direct finding (the phone number) + its sub-techniques
    assert scores["T1589.002"] == scores["T1589.003"] == 1
    assert scores["T1589"] == 3
    assert all(t["tactic"] == "reconnaissance" for t in layer["techniques"])
    json.dumps(layer)  # must be serialisable


# ------------------------------------------------------------------------------ STIX
def test_stix_bundle_is_valid_and_round_trips():
    bundle = build_bundle(sample_investigation(), sample_graph())
    parsed = stix2.parse(bundle.serialize(), allow_custom=False)  # strict spec validation
    types = {o.type for o in parsed.objects}
    assert {
        "report",
        "identity",
        "marking-definition",
        "domain-name",
        "ipv4-addr",
        "email-addr",
        "autonomous-system",
        "vulnerability",
        "network-traffic",
        "software",
        "x509-certificate",
        "url",
        "relationship",
        "attack-pattern",
    } <= types


def test_stix_report_references_everything_and_is_tlp_amber():
    bundle = build_bundle(sample_investigation(), sample_graph())
    report = next(o for o in bundle.objects if o.type == "report")
    ids = {o.id for o in bundle.objects}
    assert set(report.object_refs) <= ids
    assert report.object_marking_refs == [stix2.TLP_AMBER.id]
    assert "1 phone" in report.description  # unsupported types are disclosed, not silently dropped


def test_stix_ids_are_deterministic_across_exports():
    a = build_bundle(sample_investigation(), sample_graph())
    b = build_bundle(sample_investigation(), sample_graph())
    assert sorted(o.id for o in a.objects) == sorted(o.id for o in b.objects)


def test_stix_relationships_use_stix_ids():
    bundle = build_bundle(sample_investigation(), sample_graph())
    rels = [o for o in bundle.objects if o.type == "relationship"]
    assert {r.relationship_type for r in rels} == {"resolves-to", "subdomain-of", "exposes"}
    ids = {o.id for o in bundle.objects}
    assert all(r.source_ref in ids and r.target_ref in ids for r in rels)


@pytest.mark.parametrize("value", ["not-an-ip", "AS-weird"])
def test_malformed_values_are_skipped_not_crashing(value):
    g = IntelligenceGraph("inv_test")
    g.add_entity(Entity.create(EntityType.DOMAIN, "example.com"), is_seed=True)
    etype = EntityType.IP_ADDRESS if "ip" in value else EntityType.ASN
    g.add_entity(Entity.create(etype, value, depth=1))
    stix2.parse(build_bundle(sample_investigation(), g).serialize())


# ------------------------------------------------------------------------------- API
def test_intel_endpoints(client):
    from tests.test_persistence import _seed_finished_investigation

    inv_id = _seed_finished_investigation(client)
    mapping = client.get(f"/api/investigation/{inv_id}/attack").json()
    assert mapping["tactic"]["id"] == "TA0043" and mapping["technique_count"] >= 1

    layer = client.get(f"/api/investigation/{inv_id}/export/navigator")
    assert layer.status_code == 200 and "attachment" in layer.headers["content-disposition"]

    resp = client.get(f"/api/investigation/{inv_id}/export/stix")
    assert resp.headers["content-type"].startswith("application/stix+json")
    stix2.parse(resp.text)

    formats = {
        e["details"]["format"] for e in client.get("/api/audit", params={"action": "investigation.export"}).json()
    }
    assert {"attack-navigator", "stix-2.1"} <= formats
    modules = client.get("/api/modules").json()
    assert all("attack_techniques" in m and "active" in m for m in modules)
