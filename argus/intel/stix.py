"""STIX 2.1 export - the OASIS standard for exchanging cyber threat intelligence.

Lets an investigation be imported into threat-intelligence platforms such as
OpenCTI or MISP, or shared with another team in a vendor-neutral format.

Mapping
-------
* Observables (SCOs): domains, IPs, email addresses, ASNs, X.509 certificates,
  software, URLs (social profiles) and user accounts. STIX derives their IDs
  deterministically from their values, so the same IP exported twice gets the
  same ID - which is what lets platforms de-duplicate across reports.
* Domain objects (SDOs): people/organisations -> ``identity``; CVEs ->
  ``vulnerability``; mapped ATT&CK techniques -> ``attack-pattern``.
* Graph edges -> ``relationship`` objects.
* Everything is wrapped in a ``report`` marked TLP:AMBER (limited disclosure):
  an OSINT dossier about a target is sensitive by default.

Entity types with no STIX equivalent (phone numbers, raw DNS policy records) are
counted in the report description rather than invented as custom objects.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Any

import stix2

from argus import __version__
from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Investigation
from argus.intel.attack import map_investigation

# Fixed namespace so Argus's own identity and per-investigation SDO IDs are stable across exports.
ARGUS_NAMESPACE = uuid.UUID("6f6b0c1e-9a65-4a0f-8f36-2a7a1c0f4e11")
ARGUS_IDENTITY = stix2.Identity(
    id=f"identity--{uuid.uuid5(ARGUS_NAMESPACE, 'argus-osint')}",
    name="Argus OSINT",
    identity_class="system",
    description="Autonomous OSINT reconnaissance and graph link analysis platform",
    created=datetime(2025, 1, 1, tzinfo=timezone.utc),
    modified=datetime(2025, 1, 1, tzinfo=timezone.utc),
)
MARKING = stix2.TLP_AMBER


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def _sdo_id(kind: str, *parts: str) -> str:
    return f"{kind}--{uuid.uuid5(ARGUS_NAMESPACE, '|'.join(parts))}"


def _sdo_common(investigation_id: str) -> dict[str, Any]:
    return {"created_by_ref": ARGUS_IDENTITY.id, "object_marking_refs": [MARKING.id]}


def _observable(entity: Entity, ip_ids: dict[str, str]) -> Any | None:
    """Translate one entity into a STIX Cyber-observable Object, or None if unsupported."""
    t, v, md = entity.type, entity.value, entity.metadata
    if t in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
        return stix2.DomainName(value=v.lower())
    if t == EntityType.IP_ADDRESS:
        try:
            ip = ipaddress.ip_address(v)
        except ValueError:
            return None
        return stix2.IPv4Address(value=v) if ip.version == 4 else stix2.IPv6Address(value=v)
    if t == EntityType.EMAIL:
        return stix2.EmailAddress(value=v.lower())
    if t == EntityType.ASN:
        digits = v.upper().removeprefix("AS")
        if not digits.isdigit():
            return None
        return stix2.AutonomousSystem(number=int(digits), name=md.get("as_name") or entity.label)
    if t == EntityType.CERTIFICATE and md.get("sha256_fingerprint"):
        cert: dict[str, Any] = {"hashes": {"SHA-256": md["sha256_fingerprint"]}}
        if md.get("serial"):
            cert["serial_number"] = md["serial"]
        if md.get("issuer"):
            cert["issuer"] = md["issuer"]
        if md.get("subject_cn"):
            cert["subject"] = f"CN={md['subject_cn']}"
        # STIX timestamps must be UTC "...Z"; parse our ISO strings into datetimes and let stix2 format them.
        for src, dst in (("valid_from", "validity_not_before"), ("valid_to", "validity_not_after")):
            when = _parse_time(md.get(src))
            if when is not None:
                cert[dst] = when
        return stix2.X509Certificate(**cert)
    if t == EntityType.TECHNOLOGY:
        return stix2.Software(name=v)
    if t == EntityType.SOCIAL_PROFILE and v.startswith(("http://", "https://")):
        return stix2.URL(value=v)
    if t == EntityType.URL and v.startswith(("http://", "https://")):
        return stix2.URL(value=v)
    if t == EntityType.USERNAME:
        return stix2.UserAccount(account_login=v)
    if t == EntityType.PORT and ":" in v:
        host, _, port = v.rpartition(":")
        if port.isdigit() and host in ip_ids:
            return stix2.NetworkTraffic(dst_ref=ip_ids[host], dst_port=int(port), protocols=["tcp"])
    return None


def _domain_object(entity: Entity, investigation_id: str) -> Any | None:
    common = _sdo_common(investigation_id)
    if entity.type in (EntityType.PERSON, EntityType.ORGANIZATION):
        cls = "individual" if entity.type == EntityType.PERSON else "organization"
        return stix2.Identity(
            id=_sdo_id("identity", investigation_id, entity.id), name=entity.value, identity_class=cls, **common
        )
    if entity.type == EntityType.LOCATION:
        return stix2.Location(
            id=_sdo_id("location", investigation_id, entity.id),
            name=entity.value,
            description="Self-declared location on a public profile",
            region="unknown",
            **common,
        )
    if entity.type == EntityType.VULNERABILITY and entity.value.upper().startswith("CVE-"):
        cve = entity.value.upper()
        return stix2.Vulnerability(
            id=_sdo_id("vulnerability", cve),  # CVE IDs are global: same CVE -> same STIX ID
            name=cve,
            external_references=[
                {"source_name": "cve", "external_id": cve, "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}
            ],
            **common,
        )
    return None


def build_bundle(investigation: Investigation, graph: IntelligenceGraph) -> stix2.Bundle:
    """Convert an investigation into a self-contained STIX 2.1 bundle."""
    inv_id = investigation.id
    objects: dict[str, Any] = {}
    entity_to_stix: dict[str, str] = {}
    unsupported: dict[str, int] = {}

    entities = sorted(graph.get_all_entities(), key=lambda e: e.type != EntityType.IP_ADDRESS)  # IPs first
    ip_ids: dict[str, str] = {}
    for entity in entities:
        obj = _observable(entity, ip_ids) or _domain_object(entity, inv_id)
        if obj is None:
            unsupported[entity.type.value] = unsupported.get(entity.type.value, 0) + 1
            continue
        objects[obj.id] = obj
        entity_to_stix[entity.id] = obj.id
        if entity.type == EntityType.IP_ADDRESS:
            ip_ids[entity.value] = obj.id

    for rel in graph.get_all_relations():
        src, dst = entity_to_stix.get(rel.source_id), entity_to_stix.get(rel.target_id)
        if not src or not dst or src == dst:
            continue
        rel_obj = stix2.Relationship(
            id=_sdo_id("relationship", inv_id, rel.id),
            source_ref=src,
            target_ref=dst,
            relationship_type=rel.type.value.lower().replace("_", "-"),
            description=rel.label,
            **_sdo_common(inv_id),
        )
        objects[rel_obj.id] = rel_obj

    for tech in map_investigation(graph)["techniques"]:
        pattern = stix2.AttackPattern(
            id=_sdo_id("attack-pattern", tech["id"]),
            name=tech["name"] if tech["parent"] == tech["id"] else f"{tech['parent_name']}: {tech['name']}",
            description=f"Reconnaissance exposure: {tech['count']} finding(s). Defence: {tech['defence']}",
            external_references=[{"source_name": "mitre-attack", "external_id": tech["id"], "url": tech["url"]}],
            kill_chain_phases=[{"kill_chain_name": "mitre-attack", "phase_name": "reconnaissance"}],
            **_sdo_common(inv_id),
        )
        objects[pattern.id] = pattern

    published = investigation.completed_at or datetime.now(timezone.utc)
    skipped = ", ".join(f"{n} {t}" for t, n in sorted(unsupported.items())) or "none"
    report = stix2.Report(
        id=_sdo_id("report", inv_id),
        name=f"Argus OSINT reconnaissance: {investigation.config.target}",
        description=(
            f"Investigation {inv_id} of {investigation.config.target} "
            f"({investigation.config.target_type.value}), generated by Argus {__version__}. "
            f"Entities without a STIX equivalent (not exported): {skipped}."
        ),
        published=published,
        report_types=["infrastructure"],
        object_refs=sorted(objects) or [ARGUS_IDENTITY.id],
        labels=["osint", "reconnaissance"],
        **_sdo_common(inv_id),
    )
    return stix2.Bundle(ARGUS_IDENTITY, MARKING, report, *objects.values())
