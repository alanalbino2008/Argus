"""Attack-surface drift: what changed between two investigations of the same target.

A single scan is a snapshot; real attack surfaces drift. Someone opens a database
port, a new subdomain appears, an employee turns up in a fresh breach. Comparing
consecutive scans turns Argus from a one-off tool into a monitoring system.

The comparison is keyed on Argus's deterministic IDs, so "the same thing" is
recognised across scans without fuzzy matching:

* entities - added / removed, grouped by type;
* watched facts - security-relevant metadata that changed on surviving entities
  (DMARC policy, VirusTotal detections, breach count, certificate expiry, header grade);
* attack paths - newly opened and resolved (path IDs hash the rule and its entities);
* risk delta - the change in total attack-path risk, i.e. "are we better or worse?".
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity
from argus.intel.paths import find_attack_paths

# Metadata worth alerting on when it changes: key -> human description.
WATCHED_FACTS: dict[str, str] = {
    "dmarc_policy": "DMARC policy",
    "spf": "SPF record",
    "security_headers_grade": "security header grade",
    "breach_count": "breach count",
    "expired": "certificate expired",
    "self_signed": "certificate self-signed",
    "product": "service product",
    "version": "service version",
}
MAX_LISTED = 50


def _facts(entity: Entity) -> dict[str, Any]:
    facts = {k: entity.metadata[k] for k in WATCHED_FACTS if k in entity.metadata}
    vt = entity.metadata.get("virustotal")
    if isinstance(vt, dict) and "malicious" in vt:
        facts["virustotal_malicious"] = vt["malicious"]
    return facts


def _brief(entity: Entity) -> dict[str, str]:
    return {"id": entity.id, "type": entity.type.value, "value": entity.value, "label": entity.label}


def _grouped(entities: list[Entity]) -> dict[str, list[dict[str, str]]]:
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for e in sorted(entities, key=lambda e: (e.type.value, e.value)):
        if len(groups[e.type.value]) < MAX_LISTED:
            groups[e.type.value].append(_brief(e))
    return dict(groups)


def _path_brief(path: dict[str, Any]) -> dict[str, Any]:
    return {k: path[k] for k in ("id", "rule", "title", "severity", "score")}


def compare(old: IntelligenceGraph, new: IntelligenceGraph) -> dict[str, Any]:
    """Describe how ``new`` differs from ``old`` (both graphs of the same target)."""
    old_e = {e.id: e for e in old.get_all_entities()}
    new_e = {e.id: e for e in new.get_all_entities()}
    added = [new_e[i] for i in new_e.keys() - old_e.keys()]
    removed = [old_e[i] for i in old_e.keys() - new_e.keys()]

    changed = []
    for eid in sorted(old_e.keys() & new_e.keys()):
        before, after = _facts(old_e[eid]), _facts(new_e[eid])
        diffs = {
            k: {"before": before.get(k), "after": after.get(k)}
            for k in before.keys() | after.keys()
            if before.get(k) != after.get(k) and k in after  # a fact absent from the new scan is "not checked"
        }
        if diffs:
            changed.append({**_brief(new_e[eid]), "changes": diffs})

    old_paths = {p["id"]: p for p in find_attack_paths(old)["paths"]}
    new_paths = {p["id"]: p for p in find_attack_paths(new)["paths"]}
    opened = sorted((new_paths[i] for i in new_paths.keys() - old_paths.keys()), key=lambda p: -p["score"])
    resolved = sorted((old_paths[i] for i in old_paths.keys() - new_paths.keys()), key=lambda p: -p["score"])
    # Same scenario (rule + subject) in both scans, but its risk moved - e.g. a second breach.
    shifted = [
        {**_path_brief(new_paths[i]), "score_before": old_paths[i]["score"]}
        for i in sorted(old_paths.keys() & new_paths.keys())
        if new_paths[i]["score"] != old_paths[i]["score"]
    ]
    escalated = sorted((p for p in shifted if p["score"] > p["score_before"]), key=lambda p: -p["score"])
    reduced = sorted((p for p in shifted if p["score"] < p["score_before"]), key=lambda p: -p["score"])
    old_risk = sum(p["score"] for p in old_paths.values())
    new_risk = sum(p["score"] for p in new_paths.values())

    material = bool(opened or escalated or added or changed)
    return {
        "summary": {
            "added": len(added),
            "removed": len(removed),
            "changed": len(changed),
            "new_paths": len(opened),
            "resolved_paths": len(resolved),
            "escalated_paths": len(escalated),
            "reduced_paths": len(reduced),
            "risk_before": old_risk,
            "risk_after": new_risk,
            "risk_delta": new_risk - old_risk,
            "trend": "worse" if new_risk > old_risk else "better" if new_risk < old_risk else "unchanged",
            "material": material,
        },
        "added": _grouped(added),
        "removed": _grouped(removed),
        "changed": changed[:MAX_LISTED],
        "new_paths": [_path_brief(p) for p in opened],
        "resolved_paths": [_path_brief(p) for p in resolved],
        "escalated_paths": escalated,
        "reduced_paths": reduced,
    }


def headline(diff: dict[str, Any], target: str) -> str:
    """One-line human summary, e.g. for alerts."""
    s = diff["summary"]
    parts = []
    if s["new_paths"]:
        top = diff["new_paths"][0]
        parts.append(f"{s['new_paths']} new attack path(s), worst: {top['title']} ({top['severity']})")
    if s["escalated_paths"]:
        parts.append(f"{s['escalated_paths']} path(s) escalated")
    if s["added"]:
        parts.append(f"{s['added']} new asset(s)")
    if s["changed"]:
        parts.append(f"{s['changed']} security-relevant change(s)")
    if s["resolved_paths"]:
        parts.append(f"{s['resolved_paths']} path(s) resolved")
    trend = {"worse": "risk up", "better": "risk down", "unchanged": "risk unchanged"}[s["trend"]]
    return f"{target}: " + ("; ".join(parts) if parts else "no changes") + f" ({trend} {s['risk_delta']:+d})"
