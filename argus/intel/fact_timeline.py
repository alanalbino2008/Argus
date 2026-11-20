"""The facts inside a case's scans, in time: when things happened, not just when Argus looked.

A scan records *dated facts* scattered across its entities: when a domain was registered and when it
expires, a certificate's validity, when a breach happened, when an account was created, when a
company was incorporated and its directors appointed, a wallet's first and last transactions, when a
page was archived, when a document was written. This module lifts every one of them onto the case
timeline, each tied to the entity, the investigation and the module that found it.

It also tells the story *between* scans: for consecutive scans of the same target, what appeared
and what disappeared (reusing the scan comparison of ``argus/intel/diff.py``).

Dates are kept at the precision they were given. "2009" is a year, not 1 January 2009 at midnight,
and the timeline says so. A fact seen by several scans appears once, listing every scan that saw it.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from itertools import pairwise
from typing import Any

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Investigation, RelationType
from argus.intel.diff import compare

MAX_FACTS = 5000  # per case: a timeline, not a dump
CHANGE_SAMPLE = 8  # entities named in an "appeared" / "disappeared" entry


@dataclass(frozen=True)
class FactRule:
    path: tuple[str, ...]  # metadata path
    fact: str  # machine name of the fact
    title: Callable[[Entity], str]
    types: frozenset[EntityType] | None = None  # None: any entity type
    via: str = ""  # the record the date comes from, for the analyst


def _name(entity: Entity) -> str:
    return entity.label


def _platform(entity: Entity) -> str:
    return str(entity.metadata.get("platform") or entity.label)


RULES: tuple[FactRule, ...] = (
    FactRule(("registration_date",), "domain_registered", lambda e: f"Domain registered: {_name(e)}",
             frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN}), via="the RDAP registration record"),
    FactRule(("expiration_date",), "domain_expires", lambda e: f"Domain registration expires: {_name(e)}",
             frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN}), via="the RDAP registration record"),
    FactRule(("last_changed",), "domain_changed", lambda e: f"Domain registration last changed: {_name(e)}",
             frozenset({EntityType.DOMAIN, EntityType.SUBDOMAIN}), via="the RDAP registration record"),
    FactRule(("valid_from",), "certificate_issued", lambda e: f"Certificate valid from: {_name(e)}",
             frozenset({EntityType.CERTIFICATE}), via="the certificate itself"),
    FactRule(("valid_to",), "certificate_expires", lambda e: f"Certificate valid until: {_name(e)}",
             frozenset({EntityType.CERTIFICATE}), via="the certificate itself"),
    FactRule(("breach_date",), "breach", lambda e: f"Data breach: {e.value}", frozenset({EntityType.BREACH}), via="the breach notification service"),
    FactRule(("profile", "created_at"), "account_created", lambda e: f"Account created: {_platform(e)}", via="the platform's public profile"),
    FactRule(("created_at",), "account_created", lambda e: f"Account created: {_platform(e)}",
             frozenset({EntityType.SOCIAL_PROFILE, EntityType.USERNAME, EntityType.ORGANIZATION}), via="the platform's public profile"),
    FactRule(("incorporated",), "company_incorporated", lambda e: f"Company incorporated: {_name(e)}",
             frozenset({EntityType.ORGANIZATION}), via="the company register"),
    FactRule(("dissolved",), "company_dissolved", lambda e: f"Company dissolved: {_name(e)}",
             frozenset({EntityType.ORGANIZATION}), via="the company register"),
    FactRule(("first_seen",), "wallet_first_seen", lambda e: f"Wallet's first transaction: {_name(e)}",
             frozenset({EntityType.CRYPTO_WALLET}), via="the blockchain"),
    FactRule(("last_seen",), "wallet_last_seen", lambda e: f"Wallet's latest transaction: {_name(e)}",
             frozenset({EntityType.CRYPTO_WALLET}), via="the blockchain"),
    FactRule(("archived_on",), "archived", lambda e: f"Archived by the Internet Archive: {_name(e)}", via="the Internet Archive"),
    FactRule(("document", "created"), "document_created", lambda e: f"Document written: {_name(e)}", via="the document's own metadata"),
    FactRule(("document", "modified"), "document_modified", lambda e: f"Document last edited: {_name(e)}", via="the document's own metadata"),
    FactRule(("key_created",), "pgp_key_created", lambda e: f"PGP key created for {_name(e)}", via="the PGP keyserver"),
    FactRule(("lifecycle", "eol_date"), "end_of_life", lambda e: f"End of life (no more security fixes): {_name(e)}",
             frozenset({EntityType.TECHNOLOGY}), via="endoflife.date"),
    FactRule(("intel", "kev", "date_added"), "kev_added",
             lambda e: f"Added to CISA's exploited-vulnerabilities list: {_name(e)}",
             frozenset({EntityType.VULNERABILITY}), via="CISA's KEV catalog"),
)  # fmt: skip

_YEAR = re.compile(r"^\d{4}$")
_MONTH = re.compile(r"^\d{4}-\d{2}$")
_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def parse_date(value: Any) -> tuple[datetime, str] | None:
    """(moment, precision) for a date as sources give it: 2009, 2009-03, 2009-03-14 or a full timestamp.

    Precision is "year", "month", "day" or "time". Anything else (numbers, nonsense) is None.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    try:
        if _YEAR.match(text):
            moment, precision = datetime(int(text), 1, 1, tzinfo=timezone.utc), "year"
        elif _MONTH.match(text):
            moment, precision = datetime(int(text[:4]), int(text[5:7]), 1, tzinfo=timezone.utc), "month"
        elif _DAY.match(text):
            moment, precision = datetime.fromisoformat(text).replace(tzinfo=timezone.utc), "day"
        else:
            moment, precision = datetime.fromisoformat(text.replace("Z", "+00:00")), "time"
    except ValueError:
        return None
    if not 1900 <= moment.year <= 2200:  # placeholders such as 0001 or 9999, never a real event
        return None
    return (moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)), precision


def _get(metadata: dict[str, Any], path: tuple[str, ...]) -> Any:
    node: Any = metadata
    for part in path:
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node


def _sources(entity: Entity) -> list[str]:
    """The modules that reported an entity ("seed" is the scan's own target, not a module)."""
    return [s for s in (entity.metadata.get("sources") or [entity.source_module]) if s and s != "seed"]


def _relation_facts(graph: IntelligenceGraph) -> list[tuple[str, Any, str, Entity, str]]:
    """Officer appointments and resignations, which live on person -> company relations."""
    found = []
    for rel in graph.get_all_relations():
        if rel.type != RelationType.OFFICER_OF:
            continue
        person, company = graph.get_entity(rel.source_id), graph.get_entity(rel.target_id)
        if person is None or company is None:
            continue
        role = rel.metadata.get("role") or "officer"
        for key, fact, verb in (("appointed", "officer_appointed", "appointed"),
                                ("resigned", "officer_resigned", "resigned as")):  # fmt: skip
            if rel.metadata.get(key):
                title = f"{person.label} {verb} {role} of {company.label}"
                found.append((fact, rel.metadata[key], title, person, rel.id))
    return found


def dated_facts(investigation: Investigation, graph: IntelligenceGraph) -> list[dict[str, Any]]:
    """Every dated fact in one scan's graph, as timeline entries (unsorted, not yet de-duplicated)."""
    entries = []

    def add(fact: str, value: Any, title: str, entity: Entity, key: str, via: str) -> None:
        parsed = parse_date(value)
        if parsed is None:
            return
        moment, precision = parsed
        modules = ", ".join(_sources(entity)).replace("_", " ")
        entries.append({
            "at": moment, "kind": "fact", "fact": fact, "title": title, "precision": precision,
            "detail": f"Source: {via}" + (f" · found by {modules}" if modules else ""),
            "ref": {"type": "entity", "investigation_id": investigation.id, "entity_id": entity.id},
            "key": key,  # what makes two scans' copies of a fact the same fact
            "seen_in": [{"id": investigation.id, "target": investigation.config.target}],
        })  # fmt: skip

    for entity in graph.get_all_entities():
        for rule in RULES:
            if rule.types is not None and entity.type not in rule.types:
                continue
            value = _get(entity.metadata, rule.path)
            if value:
                add(rule.fact, value, rule.title(entity), entity, f"{entity.id}|{rule.fact}|{value}", rule.via)
    for fact, value, title, person, rel_id in _relation_facts(graph):
        add(fact, value, title, person, f"{rel_id}|{fact}|{value}", "the company register")
    return entries


def scan_changes(scans: list[tuple[Investigation, IntelligenceGraph]]) -> list[dict[str, Any]]:
    """What appeared and disappeared between consecutive scans of the same target."""
    by_target: dict[tuple[str, str], list[tuple[Investigation, IntelligenceGraph]]] = {}
    for inv, graph in scans:
        by_target.setdefault((inv.config.target.strip().lower(), inv.config.target_type.value), []).append((inv, graph))
    entries = []
    for runs in by_target.values():
        runs.sort(key=lambda r: r[0].created_at)
        for (old_inv, old_graph), (new_inv, new_graph) in pairwise(runs):
            diff = compare(old_graph, new_graph)
            when = new_inv.completed_at or new_inv.created_at
            when = when if when.tzinfo else when.replace(tzinfo=timezone.utc)
            for key, verb in (("added", "appeared"), ("removed", "disappeared")):
                groups: dict[str, list[dict[str, Any]]] = diff.get(key) or {}
                total = sum(len(v) for v in groups.values())
                if not total:
                    continue
                kinds = ", ".join(
                    f"{len(v)} {t.replace('_', ' ')}" for t, v in sorted(groups.items(), key=lambda kv: -len(kv[1]))
                )
                sample = [item["label"] for items in groups.values() for item in items][:CHANGE_SAMPLE]
                more = f" and {total - len(sample)} more" if total > len(sample) else ""
                entries.append({
                    "at": when, "kind": "change", "fact": f"entities_{key}", "precision": "time",
                    "title": f"{total} new on {new_inv.config.target}" if key == "added"
                    else f"{total} gone from {new_inv.config.target}",
                    "detail": f"Since the scan of {old_inv.created_at:%d %b %Y}, {verb}: {kinds}.\n"
                              f"{', '.join(sample)}{more}",
                    "ref": {"type": "investigation", "id": new_inv.id, "compared_with": old_inv.id},
                    "key": f"{new_inv.id}|{key}",
                    "seen_in": [{"id": new_inv.id, "target": new_inv.config.target}],
                })  # fmt: skip
    return entries


def case_facts(scans: list[tuple[Investigation, IntelligenceGraph]]) -> list[dict[str, Any]]:
    """Dated facts from every scan of a case plus what changed between them, de-duplicated, oldest first."""
    merged: dict[str, dict[str, Any]] = {}
    for inv, graph in sorted(scans, key=lambda s: s[0].created_at):
        for entry in dated_facts(inv, graph):
            existing = merged.get(entry["key"])
            if existing is None:
                merged[entry["key"]] = entry
            elif all(s["id"] != inv.id for s in existing["seen_in"]):
                existing["seen_in"].append(entry["seen_in"][0])
                existing["ref"] = entry["ref"]  # point at the latest scan that saw it
    entries = list(merged.values()) + scan_changes(scans)
    entries.sort(key=lambda e: e["at"])
    entries = entries[-MAX_FACTS:]
    for entry in entries:
        entry.pop("key", None)
        entry["at"] = entry["at"].isoformat()
        if len(entry["seen_in"]) > 1:
            entry["detail"] += f" · seen in {len(entry['seen_in'])} scans"
    return entries
