"""TAXII 2.1 collections: what a workspace knows, as STIX 2.1 indicators for other security tools.

Threat-intelligence platforms (OpenCTI, MISP, Microsoft Sentinel, Splunk and many others) pull
indicators from TAXII servers on a schedule. Argus serves three read-only collections per workspace:

* **tagged**: every entity the team has tagged (Phase 68) that is an observable (domain, IP address,
  email address, URL). The tags become the indicator's ``labels`` and the note its description, so
  "everything tagged ``c2``" reaches the SIEM without anyone copying it there.
* **lookalikes**: lookalike domains found by brand watches (Phase 71), with their technique.
* **fingerprint-servers**: servers found by fingerprint watches (Phase 69): the addresses sharing a
  watched favicon, JARM, HASSH or certificate.

Identifiers are deterministic (the same indicator keeps its id across pulls, so platforms update
rather than duplicate it), and ``date_added`` is when Argus first knew it, so ``added_after`` pulls
are incremental. Everything is marked TLP:AMBER, like Argus's STIX exports.
"""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone
from typing import Any

from argus.intel.stix import ARGUS_IDENTITY, ARGUS_NAMESPACE, MARKING

MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE = "application/stix+json;version=2.1"
COLLECTIONS = {
    "tagged": ("Tagged entities", "Domains, IP addresses, email addresses and URLs the team has tagged in Argus"),
    "lookalikes": ("Lookalike domains", "Domains imitating the organisation's, found in Certificate Transparency"),
    "fingerprint-servers": (
        "Fingerprint-watch servers",
        "Servers sharing a watched favicon, JARM, HASSH or certificate",
    ),
    "campaigns": (
        "Campaigns",
        "Groups of the indicators above that share infrastructure, as STIX campaigns with their indicators",
    ),
}
OBSERVABLE_TYPES = {"domain": "domain-name", "subdomain": "domain-name", "email": "email-addr", "url": "url",
                    "social_profile": "url", "ip_address": None}  # fmt: skip


def collection_id(workspace_id: str, kind: str) -> str:
    return str(uuid.uuid5(ARGUS_NAMESPACE, f"taxii|{workspace_id}|{kind}"))


def collections(workspace_id: str) -> list[dict[str, Any]]:
    return [
        {
            "id": collection_id(workspace_id, kind),
            "title": title,
            "description": description,
            "alias": kind,
            "can_read": True,
            "can_write": False,
            "media_types": [STIX_MEDIA_TYPE],
        }
        for kind, (title, description) in COLLECTIONS.items()
    ]


def kind_of(workspace_id: str, cid: str) -> str | None:
    return next((k for k in COLLECTIONS if collection_id(workspace_id, k) == cid or k == cid), None)


def _literal(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def _ip_type(value: str) -> str | None:
    try:
        return "ipv4-addr" if ipaddress.ip_address(value).version == 4 else "ipv6-addr"
    except ValueError:
        return None


def pattern_for(entity_type: str, value: str) -> str | None:
    value = value.strip()
    if entity_type == "ip_address":
        kind = _ip_type(value)
        return f"[{kind}:value = {_literal(value)}]" if kind else None
    kind = OBSERVABLE_TYPES.get(entity_type)
    if kind is None:
        return None
    if kind == "url" and not value.startswith(("http://", "https://")):
        return None
    if kind in ("domain-name", "email-addr"):
        value = value.lower()
    return f"[{kind}:value = {_literal(value)}]"


def _stamp(value: str | None) -> str:
    """A STIX timestamp (UTC, milliseconds, Z)."""
    try:
        moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        moment = datetime(2025, 1, 1, tzinfo=timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.") + f"{moment.microsecond // 1000:03d}Z"


def indicator_id(workspace_id: str, kind: str, key: str) -> str:
    return f"indicator--{uuid.uuid5(ARGUS_NAMESPACE, f'taxii|{workspace_id}|{kind}|{key}')}"


def indicator(
    workspace_id: str, kind: str, key: str, *, name: str, pattern: str, created: str, modified: str | None = None,
    labels: list[str], description: str = "", indicator_types: list[str] | None = None,
) -> dict[str, Any]:  # fmt: skip
    created_at = _stamp(created)
    obj: dict[str, Any] = {
        "type": "indicator", "spec_version": "2.1",
        "id": indicator_id(workspace_id, kind, key),
        "created": created_at, "modified": max(created_at, _stamp(modified or created)),
        "name": name[:250], "pattern": pattern, "pattern_type": "stix", "valid_from": created_at,
        "labels": labels[:20], "created_by_ref": ARGUS_IDENTITY.id, "object_marking_refs": [MARKING.id],
    }  # fmt: skip
    if description:
        obj["description"] = description[:4000]
    if indicator_types:
        obj["indicator_types"] = indicator_types
    return obj


# ----------------------------------------------------------------------------- the three collections
def tagged(workspace_id: str, annotations: dict[str, dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    """(date_added, indicator) for every tagged observable."""
    out = []
    for entity_id, a in annotations.items():
        if not a.get("tags"):
            continue
        pattern = pattern_for(str(a.get("entity_type")), str(a.get("value") or ""))
        if pattern is None:
            continue
        when = str(a.get("updated_at") or "")
        out.append((_stamp(when), indicator(
            workspace_id, "tagged", entity_id, name=str(a.get("value")), pattern=pattern, created=when,
            labels=list(a["tags"]), description=str(a.get("note") or ""),
        )))  # fmt: skip
    return out


def lookalikes(
    workspace_id: str, watches: list[tuple[dict[str, Any], dict[str, str], dict[str, Any]]]
) -> list[tuple[str, dict[str, Any]]]:
    out = []
    for watch, first_seen, details in watches:
        for name, when in first_seen.items():
            info = details.get(name) or {}
            technique = str(info.get("technique") or "lookalike")
            description = (f"Imitates {watch['domain']} ({technique}: {info.get('detail') or 'lookalike domain'}); "
                           "found in Certificate Transparency by an Argus brand watch.")  # fmt: skip
            out.append((_stamp(when), indicator(
                workspace_id, "lookalikes", f"{watch['domain']}|{name}", name=str(info.get("display") or name),
                pattern=f"[domain-name:value = {_literal(name)}]", created=when,
                labels=["lookalike-domain", technique, f"brand:{watch['domain']}"], description=description,
                indicator_types=["malicious-activity"] if info.get("severity") == "high" else ["anomalous-activity"],
            )))  # fmt: skip
    return out


def split_server(server: str) -> tuple[str, str]:
    """``198.51.100.7:443`` and ``[2001:db8::5]:22`` -> (address, port); a bare address has no port."""
    if server.startswith("[") and "]:" in server:
        ip, _, port = server[1:].partition("]:")
        return ip, port
    if server.count(":") == 1:
        ip, _, port = server.partition(":")
        return ip, port
    return server.strip("[]"), ""


def fingerprint_servers(
    workspace_id: str, watches: list[tuple[dict[str, Any], dict[str, str]]]
) -> list[tuple[str, dict[str, Any]]]:
    out = []
    for watch, first_seen in watches:
        for server, when in first_seen.items():
            ip, port = split_server(server)
            kind = _ip_type(ip)
            if kind is None:
                continue
            pattern = f"[{kind}:value = {_literal(ip)}]"
            if port.isdigit():
                pattern = f"([{kind}:value = {_literal(ip)}] AND [network-traffic:dst_port = {int(port)}])"
            out.append((_stamp(when), indicator(
                workspace_id, "fingerprint-servers", f"{watch['id']}|{server}", name=server, pattern=pattern,
                created=when, labels=["fingerprint-watch", watch["engine"]],
                description=f"Shares {watch['label']} ({watch['engine']} search: {watch['query']}).",
            )))  # fmt: skip
    return out


def campaign_objects(
    workspace_id: str, campaigns: list[dict[str, Any]], indicators: dict[str, tuple[str, dict[str, Any]]]
) -> list[tuple[str, dict[str, Any]]]:
    """A STIX ``campaign`` per campaign, ``indicates`` relationships from its members' indicators (the
    same ids as in the other collections, so platforms link rather than duplicate), and those indicators."""
    out: list[tuple[str, dict[str, Any]]] = []
    included: set[str] = set()
    for campaign in campaigns:
        member_ids = []
        for member in campaign["members"]:
            if member["kind"] == "lookalike":
                member_ids.append(indicator_id(workspace_id, "lookalikes", f"{member.get('brand')}|{member['value']}"))
            for watch_id, server in member.get("servers") or []:
                member_ids.append(indicator_id(workspace_id, "fingerprint-servers", f"{watch_id}|{server}"))
            if member.get("entity_id"):
                member_ids.append(indicator_id(workspace_id, "tagged", member["entity_id"]))
        member_ids = [i for i in dict.fromkeys(member_ids) if i in indicators]
        if len(member_ids) < 2:
            continue
        first, last = (
            _stamp(campaign.get("first_seen")),
            _stamp(campaign.get("last_seen") or campaign.get("first_seen")),
        )
        key = f"taxii|{workspace_id}|campaign|{campaign['id']}"
        cid = f"campaign--{uuid.uuid5(ARGUS_NAMESPACE, key)}"
        evidence = "; ".join(
            f"{link['label']}: {link['value']} ({len(link['members'])})" for link in campaign["links"][:5]
        )
        brands = ", ".join(campaign.get("brands") or [])
        out.append((first, {
            "type": "campaign", "spec_version": "2.1", "id": cid, "created": first, "modified": max(first, last),
            "name": campaign["name"], "first_seen": first, "last_seen": max(first, last),
            "description": (f"Infrastructure shared by {campaign['size']} items" + (f" imitating {brands}" if brands else "")
                            + f". Linked by: {evidence}. Severity: {campaign['severity']}."),
            "labels": [f"severity:{campaign['severity']}", *[f"brand:{b}" for b in campaign.get("brands") or []]],
            "created_by_ref": ARGUS_IDENTITY.id, "object_marking_refs": [MARKING.id],
        }))  # fmt: skip
        for mid in member_ids:
            rid = f"relationship--{uuid.uuid5(ARGUS_NAMESPACE, f'taxii|{workspace_id}|indicates|{mid}|{cid}')}"
            added = indicators[mid][0]
            out.append((max(first, added), {
                "type": "relationship", "spec_version": "2.1", "id": rid, "created": max(first, added),
                "modified": max(first, added), "relationship_type": "indicates", "source_ref": mid, "target_ref": cid,
                "created_by_ref": ARGUS_IDENTITY.id, "object_marking_refs": [MARKING.id],
            }))  # fmt: skip
            if mid not in included:
                included.add(mid)
                out.append(indicators[mid])
    return out


def page(
    objects: list[tuple[str, dict[str, Any]]], *, added_after: str | None, limit: int, start: int,
    match_ids: set[str] | None = None, match_types: set[str] | None = None,
) -> tuple[list[tuple[str, dict[str, Any]]], int | None]:  # fmt: skip
    """Filter and page ``objects`` (oldest first). Returns the page and the next start, if any."""
    after = _stamp(added_after) if added_after else None
    chosen = sorted(objects, key=lambda o: (o[0], o[1]["id"]))
    chosen = [o for o in chosen if (after is None or o[0] > after)
              and (not match_ids or o[1]["id"] in match_ids) and (not match_types or o[1]["type"] in match_types)]  # fmt: skip
    window = chosen[start : start + limit]
    return window, (start + limit if start + limit < len(chosen) else None)
