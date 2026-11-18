"""Bringing the people a scan found into a case, with the relationships between them.

A scan of a company finds its directors and owners; a scan of a username finds the accounts and
the name behind them; an email scan finds the person, their accounts and their phone. Those people
belong in the case, where they can be linked, profiled and followed, without retyping them.

:func:`proposals` turns a scan's graph into case entries:

* **who**: people, organisations, accounts, usernames, email addresses, phone numbers, wallets and
  places, each with what the scan learned about them (role, date of birth, nationality,
  platform...) and where it came from;
* **how they relate**: the scan's relations between them, as relationship kinds (an officer of a
  company becomes ``director``, someone with significant control ``owner``, an account's owner
  ``uses``, two wallets spent together ``shares_wallet``...).

Already-present entries are recognised (the same kind and value, ignoring case and spacing) and
never added twice. Organisations and things found only *about* a third party (``out_of_scope``),
and very weak finds, are left out.

Done **automatically** when a scan linked to a case finishes, for people and organisations the
scan is fairly sure of (:func:`automatic`), and by hand for the rest, ticked in a list.
"""

from __future__ import annotations

from typing import Any

from argus.core.models import EntityType, RelationType
from argus.intel.relationships import norm

CASE_TYPES = {
    EntityType.PERSON: "person", EntityType.ORGANIZATION: "organisation", EntityType.USERNAME: "username",
    EntityType.SOCIAL_PROFILE: "account", EntityType.EMAIL: "email", EntityType.PHONE: "phone",
    EntityType.CRYPTO_WALLET: "wallet", EntityType.LOCATION: "location",
}  # fmt: skip
KEEP = ("role", "born", "nationality", "occupation", "country_of_residence", "appointed", "resigned", "platform",
        "username", "company_number", "company_status", "incorporated", "registered_address", "chain", "origin",
        "found_on", "jurisdiction", "lei")  # fmt: skip
AUTOMATIC_TYPES = {"person", "organisation"}
AUTOMATIC_MIN = 0.8  # how sure a scan must be for an automatic import
MANUAL_MIN = 0.4
MAX_AUTOMATIC = 60


def _kind(rel: Any, src_type: str, dst_type: str) -> tuple[str, bool] | None:
    """(relationship kind, whether the case link runs the other way) for a scan relation."""
    rtype = rel.type
    if rtype == RelationType.OFFICER_OF:
        return "director", False
    if rtype == RelationType.CONTROLS:
        return "owner", False
    if rtype == RelationType.SAME_WALLET:
        return "shares_wallet", False
    if rtype == RelationType.HAS_ACCOUNT and src_type in ("person", "username", "organisation"):
        return "uses", False
    if rtype == RelationType.BELONGS_TO:
        return ("uses", True) if dst_type in ("person", "organisation") else None
    if rtype in (RelationType.ASSOCIATED_WITH, RelationType.HAS_ACCOUNT):
        people = {"person", "organisation"}
        if src_type in people and dst_type not in people:
            return "uses", False
        if dst_type in people and src_type not in people:
            return "uses", True
        if src_type in people and dst_type in people:
            return "associate", False
    return None


def proposals(
    graph: Any, items: list[dict[str, Any]], *, scan_label: str, min_confidence: float = MANUAL_MIN
) -> dict[str, Any]:
    """What a scan's graph would add to the case: new entries and the relationships between them."""
    existing: dict[tuple[str, str], str] = {}
    for i in items:
        if i["kind"] == "entity":
            data = i.get("data") or {}
            existing[(str(data.get("type")), norm(str(data.get("value") or i["title"]), str(data.get("type"))))] = i[
                "id"
            ]
    linked = {frozenset((str((i.get("data") or {}).get("from")), str((i.get("data") or {}).get("to"))))
              for i in items if i["kind"] == "link"}  # fmt: skip

    entries: dict[str, dict[str, Any]] = {}  # graph entity id -> proposal
    for e in graph.get_all_entities():
        ctype = CASE_TYPES.get(e.type)
        if ctype is None or e.metadata.get("out_of_scope") or e.confidence < min_confidence:
            continue
        if e.type == EntityType.ORGANIZATION and str(e.value).lower().startswith("telecom region"):
            continue  # an artefact of older phone scans, not an organisation
        key = (ctype, norm(e.value, ctype))
        attrs = {k: str(e.metadata[k])[:300] for k in KEEP if e.metadata.get(k) not in (None, "", [], {})}
        if e.metadata.get("sanction_matches"):
            attrs["sanctions"] = (
                f"possible match on {e.metadata['sanction_matches'][0].get('list', 'a sanctions list')}"
            )
        entries[e.id] = {
            "key": e.id, "type": ctype, "value": e.value[:500], "label": e.label or e.value,
            "confidence": round(e.confidence, 2), "found_by": e.source_module, "attributes": attrs,
            "existing": existing.get(key), "automatic": ctype in AUTOMATIC_TYPES and e.confidence >= AUTOMATIC_MIN,
        }  # fmt: skip
    relationships = []
    for r in graph.get_all_relations():
        a, b = entries.get(r.source_id), entries.get(r.target_id)
        if a is None or b is None:
            continue
        mapped = _kind(r, a["type"], b["type"])
        if mapped is None:
            continue
        kind, reverse = mapped
        frm, to = (b, a) if reverse else (a, b)
        if frm["existing"] and to["existing"] and frozenset((frm["existing"], to["existing"])) in linked:
            continue
        ended = bool((r.metadata or {}).get("to"))
        relationships.append({
            "from": frm["key"], "to": to["key"], "relation": kind, "label": r.label or "",
            "confidence": "confirmed" if min(frm["confidence"], to["confidence"]) >= 0.9 and r.confidence >= 0.9 else "likely",
            "since": str((r.metadata or {}).get("from") or "")[:10] or None,
            "until": str((r.metadata or {}).get("to") or "")[:10] or None,
            "why": f"Found by the scan of {scan_label}" + (" (ended)" if ended else ""),
        })  # fmt: skip
    return {"entities": sorted(entries.values(), key=lambda p: (p["existing"] is not None, p["type"] != "person",
                                                                -p["confidence"], p["value"].lower())),
            "relationships": relationships}  # fmt: skip


def automatic(found: dict[str, Any]) -> dict[str, Any]:
    """The part of :func:`proposals` added without asking: confident people and organisations, and
    the relationships between them (or with entries already in the case)."""
    chosen = {p["key"] for p in found["entities"] if p["automatic"] and not p["existing"]}
    chosen = set(sorted(chosen)[:MAX_AUTOMATIC])
    known = chosen | {p["key"] for p in found["entities"] if p["existing"]}
    people = {p["key"] for p in found["entities"] if p["type"] in AUTOMATIC_TYPES}
    rels = [r for r in found["relationships"] if r["from"] in known and r["to"] in known
            and r["from"] in people and r["to"] in people and (r["from"] in chosen or r["to"] in chosen)]  # fmt: skip
    return {"entities": [p for p in found["entities"] if p["key"] in chosen], "relationships": rels}


def _set_iso(value: Any) -> str | None:
    """A relationship date the case accepts (year, year-month or date), or None."""
    text = str(value or "")[:10]
    if len(text) in (4, 7, 10) and text[:4].isdigit():
        return text
    return None


def _wording(rel: dict[str, Any]) -> str:
    """The scan's own words for a role ("director (resigned)", "Significant control"), read as a relationship."""
    label = str(rel.get("label") or "").strip()
    if rel["relation"] not in ("director", "owner") or not label:
        return ""  # the kind's own wording ("uses", "shares a wallet with") reads better
    return label if label.lower().endswith(" of") else f"{label} of"


def as_case_items(
    selected: dict[str, Any], *, scan_id: str, scan_label: str
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """(entity item bodies, link bodies with ``from``/``to`` still as scan keys or case ids)."""
    entities = [{"kind": "entity", "title": p["value"],
                 "body": f"Added from the scan of {scan_label} (found by {p['found_by']}, confidence {p['confidence']:.0%})",
                 "data": {"type": p["type"], "value": p["value"], "attributes": p["attributes"],
                          "source_investigation_id": scan_id, "source_entity_id": p["key"]},
                 "key": p["key"]} for p in selected["entities"]]  # fmt: skip
    links = []
    for r in selected["relationships"]:
        data = {"from": r["from"], "to": r["to"], "relation": r["relation"], "label": _wording(r),
                "confidence": r["confidence"], "why": r["why"]}  # fmt: skip
        for key in ("since", "until"):
            if _set_iso(r.get(key)):
                data[key] = _set_iso(r[key])
        links.append({"kind": "link", "title": "", "body": "", "data": data})
    return entities, links
