"""One person's (or organisation's) profile: everything the case knows about them, in one place.

Built from the case itself, never from new searches:

* **who**: their name, the details recorded about them, notes, where they came from;
* **relationships**: every link to other people and organisations, with its kind, dates and how
  sure it is;
* **accounts and contacts**: usernames, accounts, emails, phone numbers, wallets and websites
  linked to them;
* **places**: addresses and locations linked to them or recorded about them;
* **mentions**: the notes, events and evidence documents that name them (or their usernames and
  contacts), with the passage around each mention;
* **timeline**: dated events that name them, and when their relationships began and ended;
* **what scans found**: from the scans linked to the case, for the same name or contacts: date of
  birth and nationality from registers, directorships, possible sanctions matches (with any
  details that contradict them), Offshore Leaks, and public profile details;
* **place in the network**: how connected they are, their group, and whether they are a key person
  or a go-between.

Protected people (for example, children) have no profile, and are blanked out of every passage
shown in others' profiles.
"""

from __future__ import annotations

import re
from typing import Any

from argus.core.models import RelationType
from argus.intel.relationships import kind_info, norm, protected, redact_protected

IDENTIFIER_TYPES = ("username", "account", "email", "phone", "wallet", "domain", "ip")
PLACE_TYPES = ("address", "location")
SNIPPET = 140
MAX_MENTIONS = 40


def _snippets(text: str, pattern: re.Pattern[str], limit: int = 3) -> list[str]:
    out = []
    for m in pattern.finditer(text):
        start, end = max(0, m.start() - SNIPPET), min(len(text), m.end() + SNIPPET)
        passage = " ".join(text[start:end].split())
        out.append(("…" if start else "") + passage + ("…" if end < len(text) else ""))
        if len(out) >= limit:
            break
    return out


def _graph_facts(graphs: list[tuple[str, str, Any]], names: set[str], kind: str) -> list[dict[str, Any]]:
    """What linked scans found about the same person or organisation (by name), or their contacts."""
    out = []
    for inv_id, target, graph in graphs:
        entities = {e.id: e for e in graph.get_all_entities()}
        matches = [e for e in entities.values() if norm(e.value, kind) in names and not e.metadata.get("out_of_scope")]
        if not matches:
            continue
        facts: dict[str, Any] = {}
        sanctions, leaks, appointments, profiles = [], [], [], []
        for e in matches:
            md = e.metadata
            for key in ("born", "nationality", "occupation", "country_of_residence", "company_number", "company_status",
                        "incorporated", "registered_address", "jurisdiction", "legal_name"):  # fmt: skip
                if md.get(key) and key not in facts:
                    facts[key] = md[key]
            sanctions += [{"list": s.get("list"), "name": s.get("name"), "score": s.get("score"),
                           "conflicts": s.get("conflicts") or []} for s in md.get("sanction_matches") or []]  # fmt: skip
            leaks += [{"name": h.get("name"), "url": h.get("url")} for h in md.get("offshore_leaks") or []]
            if md.get("profile"):
                profiles.append({"account": e.label or e.value, **{k: v for k, v in md["profile"].items()
                                                                    if k in ("display_name", "bio", "location")}})  # fmt: skip
            for r in graph.get_all_relations():
                if r.source_id == e.id and r.type in (RelationType.OFFICER_OF, RelationType.CONTROLS):
                    company = entities.get(r.target_id)
                    if company is not None:
                        appointments.append({"company": company.label or company.value, "role": r.label,
                                             "from": (r.metadata or {}).get("from"), "to": (r.metadata or {}).get("to")})  # fmt: skip
        out.append({"investigation_id": inv_id, "scan": target, "facts": facts, "sanctions": sanctions[:5],
                    "offshore_leaks": leaks[:5], "appointments": appointments[:40], "profiles": profiles[:10]})  # fmt: skip
    return out


def build_profile(items: list[dict[str, Any]], item_id: str, documents: list[dict[str, Any]],
                  graphs: list[tuple[str, str, Any]], nodes: dict[str, dict[str, Any]],
                  analysis: dict[str, Any]) -> dict[str, Any]:  # fmt: skip
    me = next(i for i in items if i["id"] == item_id)
    data = me.get("data") or {}
    kind = str(data.get("type") or "other")
    if protected(me):
        return {"id": item_id, "type": kind, "name": "Protected person", "protected": True,
                "message": "This person is protected (for example, a child): Argus builds no profile of them."}  # fmt: skip
    items, documents = redact_protected(items, documents)
    by_id = {i["id"]: i for i in items}
    name = str(data.get("value") or me["title"])

    relationships, identifiers, places = [], [], []
    for i in items:
        d = i.get("data") or {}
        if i["kind"] != "link" or item_id not in (d.get("from"), d.get("to")):
            continue
        other_id = d["to"] if d.get("from") == item_id else d.get("from")
        other = by_id.get(other_id)
        if other is None:
            continue
        info = kind_info(d.get("relation"))
        outgoing = d.get("from") == item_id
        od = other.get("data") or {}
        row = {"link_id": i["id"], "other_id": other_id, "other": nodes.get(str(other_id), {}).get("label") or od.get("value"),
               "other_type": od.get("type"), **info, "text": d.get("label") or info["label"], "outgoing": outgoing,
               "confidence": d.get("confidence", "likely"), "since": d.get("since"), "until": d.get("until"),
               "why": d.get("why")}  # fmt: skip
        if od.get("type") in IDENTIFIER_TYPES:
            identifiers.append(row)
        elif od.get("type") in PLACE_TYPES:
            places.append(row)
        else:
            relationships.append(row)
    for key, value in (data.get("attributes") or {}).items():
        if "address" in key.lower() or key.lower() in ("lives in", "location", "city", "country_of_residence"):
            places.append({"other": value, "text": key, "confidence": "recorded", "other_type": "address"})

    # Mentions: the name, and the person's own usernames, accounts and contacts.
    aliases = {name, *(r["other"] for r in identifiers if r.get("other"))}
    aliases = {a for a in aliases if a and len(str(a)) >= 4 and a != "Protected person"}
    pattern = re.compile("|".join(r"(?<!\w)" + re.escape(str(a)) + r"(?!\w)" for a in sorted(aliases, key=len, reverse=True)),
                         re.I)  # fmt: skip
    mentions, timeline = [], []
    for i in items:
        if i["id"] == item_id or i["kind"] not in ("note", "event"):
            continue
        text = f"{i.get('title') or ''}\n{i.get('body') or ''}"
        passages = _snippets(text, pattern)
        if passages:
            mentions.append({"kind": i["kind"], "id": i["id"], "title": i.get("title"), "when": i.get("occurred_at"),
                             "passages": passages})  # fmt: skip
            if i["kind"] == "event" and i.get("occurred_at"):
                timeline.append({"date": i["occurred_at"][:10], "text": i.get("title"), "source": "event"})
    for doc in documents:
        passages = _snippets(doc.get("text") or "", pattern) if doc.get("text") else []
        if passages:
            mentions.append({"kind": "evidence", "id": doc.get("id"), "title": doc.get("title"),
                             "when": doc.get("captured_at"), "passages": passages})  # fmt: skip
    for r in relationships:
        if r.get("since"):
            timeline.append({"date": r["since"], "text": f"Began: {r['text']} {r['other']}", "source": "relationship"})
        if r.get("until"):
            timeline.append({"date": r["until"], "text": f"Ended: {r['text']} {r['other']}", "source": "relationship"})

    names = {norm(name, kind)} | {norm(str(r["other"]), str(r.get("other_type") or "")) for r in identifiers}
    scans = _graph_facts(graphs, names, kind)
    for s in scans:
        for a in s["appointments"]:
            if a.get("from"):
                timeline.append({"date": str(a["from"])[:10], "text": f"Appointed: {a['role']} of {a['company']}",
                                 "source": "register"})  # fmt: skip
            if a.get("to"):
                timeline.append({"date": str(a["to"])[:10], "text": f"Left: {a['role']} of {a['company']}",
                                 "source": "register"})  # fmt: skip
    registered = {(t["date"][:10], t["text"].split(" of ", 1)[-1]) for t in timeline if t["source"] == "register"}
    timeline = [t for t in timeline if not (t["source"] == "relationship"
                                            and any(t["date"][:10] == d and t["text"].endswith(company) for d, company in registered))]  # fmt: skip
    timeline = sorted({(t["date"], t["text"]): t for t in timeline}.values(), key=lambda t: t["date"])

    node = nodes.get(item_id, {})
    cluster = node.get("cluster")
    network = {
        "connections": node.get("degree", 0), "group": None if cluster is None else cluster + 1,
        "group_size": next((c["size"] for c in analysis.get("clusters", []) if c["id"] == cluster), 0),
        "key_person": any(p["id"] == item_id for p in analysis.get("key_people", [])),
        "go_between": any(p["id"] == item_id for p in analysis.get("bridges", [])),
    }  # fmt: skip
    return {
        "id": item_id, "type": kind, "name": name, "protected": False,
        "attributes": data.get("attributes") or {}, "notes": me.get("body") or "",
        "added_by": me.get("created_by"), "added_at": me.get("created_at"),
        "from_scan": data.get("source_investigation_id"),
        "relationships": relationships, "identifiers": identifiers, "places": places,
        "mentions": mentions[:MAX_MENTIONS], "timeline": timeline, "scans": scans, "network": network,
    }  # fmt: skip
