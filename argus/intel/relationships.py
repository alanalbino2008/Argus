"""Human relationships in a case: what kinds there are, which ones the material already shows, and
how the network fits together.

**Kinds of relationship.** A link between two people (or a person and an organisation) has a
*kind*, so the network can be read at a glance and filtered: family, work, business, social,
and shared details (the same phone, address, email or wallet). Each kind belongs to a group, and
says whether it reads the same both ways (``sibling``) or not (``parent of``).

**Relationships Argus finds itself** (:func:`discover`). From the case's own material, without
guessing:

* **co-directors**: two people who are officers of the same company, from the company registers
  found by scans;
* **officer or owner**: a person who is an officer of, or controls, a company in the case;
* **shared details**: two people or organisations linked to the same phone number, email
  address, postal address, wallet or website, or with the same detail recorded about them;
* **same employer**: two people whose recorded employer is the same;
* **named together**: two people both named in the same note or evidence document.

Every suggestion names its evidence and how sure it is, and is only a suggestion: the
investigator decides which to add.

**The network** (:func:`analyse`): who is central, who bridges groups, which groups exist, who is
not connected yet, and the shortest chain between any two people (:func:`path`). Weaker links
count as longer, so the path shown is the best-supported one.

**Children are never profiled.** A person marked *protected* (for example, a child) appears in the
network as "Protected person", is left out of suggestions and of the AI analyst's material
(their name is blanked out of the notes and documents it reads), and is never profiled.
"""

from __future__ import annotations

import re
import unicodedata
from collections import defaultdict
from itertools import combinations, pairwise
from typing import Any

import networkx as nx

# kind -> (group, label, reads the same both ways)
KINDS: dict[str, tuple[str, str, bool]] = {
    "spouse": ("family", "spouse or partner of", True),
    "parent": ("family", "parent of", False),
    "sibling": ("family", "sibling of", True),
    "relative": ("family", "relative of", True),
    "employee": ("work", "works for", False),
    "colleague": ("work", "colleague of", True),
    "director": ("work", "director or officer of", False),
    "co_director": ("work", "co-director with", True),
    "owner": ("business", "owns or controls", False),
    "business_partner": ("business", "business partner of", True),
    "client": ("business", "client of", False),
    "pays": ("business", "pays or funds", False),
    "friend": ("social", "friend of", True),
    "associate": ("social", "associate of", True),
    "communicates": ("social", "communicates with", True),
    "follows": ("social", "follows online", False),
    "shares_phone": ("shared", "shares a phone number with", True),
    "shares_email": ("shared", "shares an email address with", True),
    "shares_address": ("shared", "shares an address with", True),
    "shares_wallet": ("shared", "shares a wallet with", True),
    "shares_website": ("shared", "shares a website with", True),
    "uses": ("shared", "uses", False),
    "mentioned_with": ("other", "named together with", True),
    "other": ("other", "linked to", True),
}
GROUPS = ("family", "work", "business", "social", "shared", "other")
WEIGHT = {"confirmed": 1.0, "likely": 2.0, "possible": 3.0}  # a weaker link is a longer path
PEOPLE_TYPES = {"person", "organisation"}
SHARED = {"phone": "shares_phone", "email": "shares_email", "address": "shares_address", "location": "shares_address",
          "wallet": "shares_wallet", "domain": "shares_website"}  # fmt: skip
ATTRIBUTE_WORDS = (("phone", ("phone", "mobile", "tel", "whatsapp")), ("email", ("email", "e-mail", "mail")),
                   ("wallet", ("wallet", "bitcoin", "crypto")), ("address", ("address", "lives at", "home")),
                   ("domain", ("website", "domain", "site")))  # fmt: skip
EMPLOYER_WORDS = ("employer", "works at", "works for", "company", "organisation", "organization", "job")


def attribute_kind(key: str) -> str | None:
    """What kind of detail an attribute holds, from how the investigator labelled it ("Home address")."""
    label = key.lower().strip()
    for kind, words in ATTRIBUTE_WORDS:
        if any(w in label for w in words):
            return kind
    return None


def is_employer(key: str) -> bool:
    return any(w in key.lower() for w in EMPLOYER_WORDS)


def kind_info(kind: str | None) -> dict[str, Any]:
    group, label, symmetric = KINDS.get(kind or "other", KINDS["other"])
    return {"kind": kind if kind in KINDS else "other", "group": group, "label": label, "symmetric": symmetric}


def protected(item: dict[str, Any]) -> bool:
    attrs = (item.get("data") or {}).get("attributes") or {}
    return str(attrs.get("protected", "")).lower() in ("true", "yes", "1") or bool(
        (item.get("data") or {}).get("protected")
    )


def norm(value: str, kind: str = "") -> str:
    text = unicodedata.normalize("NFKC", str(value)).strip().lower()
    if kind == "phone":
        return re.sub(r"[^\d+]", "", text)
    if kind in ("address", "location"):
        return re.sub(r"[^a-z0-9]+", " ", text).strip()
    if kind == "domain":
        return text.removeprefix("https://").removeprefix("http://").removeprefix("www.").strip("/")
    return text


# ---------------------------------------------------------------------------- the network
def entity_nodes(items: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    out = {}
    for i in items:
        if i["kind"] != "entity":
            continue
        data = i.get("data") or {}
        hidden = protected(i)
        out[i["id"]] = {"id": i["id"], "type": data.get("type", "other"),
                        "label": "Protected person" if hidden else str(data.get("value") or i["title"])[:120],
                        "protected": hidden,
                        "attributes": {} if hidden else dict(data.get("attributes") or {})}  # fmt: skip
    return out


def link_edges(items: list[dict[str, Any]], nodes: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    edges = []
    for i in items:
        data = i.get("data") or {}
        if i["kind"] != "link" or data.get("from") not in nodes or data.get("to") not in nodes:
            continue
        info = kind_info(data.get("relation"))
        edges.append({"id": i["id"], "from": data["from"], "to": data["to"], **info,
                      "text": data.get("label") or info["label"], "confidence": data.get("confidence", "likely"),
                      "since": data.get("since"), "until": data.get("until"), "evidence": data.get("evidence") or []})  # fmt: skip
    return edges


def _graph(nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]]) -> nx.Graph:
    g = nx.Graph()
    g.add_nodes_from(nodes)
    for e in edges:
        w = WEIGHT.get(e["confidence"], 2.0)
        if g.has_edge(e["from"], e["to"]) and g[e["from"]][e["to"]]["weight"] <= w:
            continue
        g.add_edge(e["from"], e["to"], weight=w, edge=e["id"])
    return g


def analyse(nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]]) -> dict[str, Any]:
    """Centrality, groups and loose ends of the case's network."""
    g = _graph(nodes, edges)
    if not g.number_of_nodes():
        return {"clusters": [], "key_people": [], "bridges": [], "isolated": []}
    degree = dict(g.degree())
    between = nx.betweenness_centrality(g, weight="weight") if g.number_of_edges() else {}
    connected = g.subgraph([n for n in g if degree[n]])
    clusters: list[list[str]] = []
    if connected.number_of_edges():
        clusters = [sorted(c) for c in nx.algorithms.community.greedy_modularity_communities(connected, weight=None)]
    cluster_of = {n: i for i, c in enumerate(clusters) for n in c}
    for n in nodes:
        nodes[n].update(degree=degree.get(n, 0), betweenness=round(between.get(n, 0.0), 4), cluster=cluster_of.get(n))
    visible = [n for n in nodes if not nodes[n]["protected"]]
    key = sorted((n for n in visible if degree.get(n)), key=lambda n: (-degree[n], -between.get(n, 0)))[:5]
    bridges = sorted((n for n in visible if between.get(n, 0) > 0.05), key=lambda n: -between[n])[:5]
    return {
        "clusters": [{"id": i, "members": c, "size": len(c)} for i, c in enumerate(clusters)],
        "key_people": [{"id": n, "label": nodes[n]["label"], "connections": degree[n]} for n in key],
        "bridges": [
            {
                "id": n,
                "label": nodes[n]["label"],
                "score": round(between[n], 3),
                "groups": sorted({cluster_of[m] for m in g[n] if m in cluster_of}),
            }
            for n in bridges
        ],
        "isolated": [{"id": n, "label": nodes[n]["label"]} for n in visible if not degree.get(n)],
    }


def path(nodes: dict[str, dict[str, Any]], edges: list[dict[str, Any]], start: str, end: str) -> dict[str, Any]:
    """The best-supported chain of links between two entities, and the connections they share."""
    g = _graph(nodes, edges)
    if start not in g or end not in g:
        return {"found": False, "steps": [], "common": []}
    common = [{"id": n, "label": nodes[n]["label"]} for n in sorted(set(g[start]) & set(g[end]))]
    try:
        route = nx.shortest_path(g, start, end, weight="weight")
    except nx.NetworkXNoPath:
        return {"found": False, "steps": [], "common": common}
    by_id = {e["id"]: e for e in edges}
    steps = []
    for a, b in pairwise(route):
        e = by_id[g[a][b]["edge"]]
        steps.append({"from": a, "to": b, "from_label": nodes[a]["label"], "to_label": nodes[b]["label"],
                      "relationship": e["text"], "confidence": e["confidence"], "edge": e["id"],
                      "reversed": e["from"] != a})  # fmt: skip
    weakest = max((WEIGHT.get(s["confidence"], 2.0) for s in steps), default=1.0)
    strength = {1.0: "confirmed", 2.0: "likely", 3.0: "possible"}.get(weakest, "likely")
    return {"found": True, "steps": steps, "hops": len(steps), "strength": strength, "common": common}


# ---------------------------------------------------------------------------- suggestions
def _suggestion(a: str, b: str, kind: str, confidence: str, why: str, text: str | None = None) -> dict[str, Any]:
    info = kind_info(kind)
    return {"from": a, "to": b, **info, "text": text or info["label"], "confidence": confidence, "why": why}


def discover(items: list[dict[str, Any]], graphs: list[Any], documents: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Relationships the case's material shows but that are not yet linked.

    ``graphs`` are the linked scans' graphs; ``documents`` are ``{"title", "text"}`` of notes and
    evidence. Protected people are never part of a suggestion.
    """
    nodes = {k: v for k, v in entity_nodes(items).items() if not v["protected"]}
    existing = {frozenset((e["from"], e["to"])) for e in link_edges(items, entity_nodes(items))}
    out: dict[tuple[frozenset[str], str], dict[str, Any]] = {}

    def add(s: dict[str, Any]) -> None:
        pair = frozenset((s["from"], s["to"]))
        if s["from"] == s["to"] or pair in existing:
            return
        key = (pair, s["kind"])
        if key not in out or WEIGHT[s["confidence"]] < WEIGHT[out[key]["confidence"]]:
            out[key] = s

    people = {k: v for k, v in nodes.items() if v["type"] in PEOPLE_TYPES}
    by_value = defaultdict(list)
    for nid, n in nodes.items():
        by_value[(n["type"], norm(n["label"], n["type"]))].append(nid)

    # 1. Shared details: linked in the case to the same phone / email / address / wallet / website ...
    holders: dict[str, set[str]] = defaultdict(set)
    detail_label: dict[str, str] = {}
    for e in link_edges(items, entity_nodes(items)):
        for a, b in ((e["from"], e["to"]), (e["to"], e["from"])):
            if a in people and b in nodes and nodes[b]["type"] in SHARED:
                holders[b].add(a)
                detail_label[b] = nodes[b]["label"]
    # ... or with the same detail recorded about them.
    for pid, p in people.items():
        for key, value in p["attributes"].items():
            kind = attribute_kind(key)
            if kind and str(value).strip():
                token = f"attr:{kind}:{norm(str(value), kind)}"
                holders[token].add(pid)
                detail_label[token] = str(value)
                nodes.setdefault(token, {"type": kind, "label": str(value)})
    for detail, owners in holders.items():
        kind = SHARED.get(nodes.get(detail, {}).get("type", ""), "other")
        for a, b in combinations(sorted(owners), 2):
            add(_suggestion(a, b, kind, "likely", f"Both are linked to {detail_label[detail]}"))

    # 2. Same recorded employer.
    employers: dict[str, set[str]] = defaultdict(set)
    employer_name: dict[str, str] = {}
    for pid, p in people.items():
        for key, value in p["attributes"].items():
            if is_employer(key) and str(value).strip():
                employers[norm(str(value))].add(pid)
                employer_name.setdefault(norm(str(value)), str(value).strip())
    for employer, staff in employers.items():
        for a, b in combinations(sorted(staff), 2):
            add(_suggestion(a, b, "colleague", "possible",
                            f"Both have {employer_name[employer]} recorded as their employer"))  # fmt: skip

    # 3. Company registers in linked scans: officers and owners, and co-directors.
    for graph in graphs:
        ents = {e.id: e for e in graph.get_all_entities()}
        officers: dict[str, list[tuple[str, str, Any]]] = defaultdict(list)
        for r in graph.get_all_relations():
            src, dst = ents.get(r.source_id), ents.get(r.target_id)
            if src is None or dst is None or r.type.value not in ("OFFICER_OF", "CONTROLS"):
                continue
            case_people = by_value.get(("person", norm(src.value, "person"))) or by_value.get(
                ("organisation", norm(src.value, "organisation"))) or []  # fmt: skip
            case_company = by_value.get(("organisation", norm(dst.value, "organisation"))) or []
            role = r.label or ("controls" if r.type.value == "CONTROLS" else "officer")
            for pid in case_people:
                officers[dst.value].append((pid, role, r.metadata or {}))
                for cid in case_company:
                    kind = "owner" if r.type.value == "CONTROLS" else "director"
                    add(_suggestion(pid, cid, kind, "confirmed", f"Company register: {role} of {dst.value}",
                                    text=f"{role} of"))  # fmt: skip
        for company, roles in officers.items():
            for (a, role_a, md_a), (b, role_b, md_b) in combinations(roles, 2):
                if a == b:
                    continue
                ended = md_a.get("to") or md_b.get("to")
                add(_suggestion(a, b, "co_director", "likely" if ended else "confirmed",
                                f"Both {role_a} / {role_b} of {company} (company register)"
                                + (" — not at the same time, possibly" if ended else "")))  # fmt: skip

    # 4. Named together in the same note or document.
    names = {pid: p["label"] for pid, p in people.items() if len(p["label"]) >= 5}
    patterns = {pid: re.compile(r"(?<!\w)" + re.escape(label) + r"(?!\w)", re.I) for pid, label in names.items()}
    for doc in documents:
        text = doc.get("text") or ""
        present = sorted(pid for pid, pattern in patterns.items() if pattern.search(text))
        if 2 <= len(present) <= 12:  # a list of everyone is not a relationship
            for a, b in combinations(present, 2):
                add(
                    _suggestion(a, b, "mentioned_with", "possible", f"Both named in “{doc.get('title', 'a document')}”")
                )

    order = {"confirmed": 0, "likely": 1, "possible": 2}
    return sorted(out.values(), key=lambda s: (order[s["confidence"]], GROUPS.index(s["group"])))


def redact_protected(items: list[dict[str, Any]], documents: list[dict[str, Any]]) -> tuple[list[Any], list[Any]]:
    """The case without its protected people: their entries become "Protected person", and their
    names are blanked out of every note and document (for the AI analyst, and anything leaving Argus)."""
    names = sorted({str((i.get("data") or {}).get("value") or i["title"]) for i in items
                    if i["kind"] == "entity" and protected(i)}, key=len, reverse=True)  # fmt: skip
    names = [n for n in names if len(n.strip()) >= 3]
    if not names:
        return items, documents
    pattern = re.compile("|".join(r"(?<!\w)" + re.escape(n) + r"(?!\w)" for n in names), re.I)

    def scrub(value: Any) -> Any:
        if isinstance(value, str):
            return pattern.sub("[protected person]", value)
        if isinstance(value, dict):
            return {k: scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [scrub(v) for v in value]
        return value

    clean_items = []
    for i in items:
        if i["kind"] == "entity" and protected(i):
            data = {"type": (i.get("data") or {}).get("type", "person"), "value": "Protected person", "attributes": {},
                    "protected": True}  # fmt: skip
            clean_items.append({**i, "title": "Protected person", "body": "", "data": data})
        else:
            clean_items.append({**i, "title": scrub(i.get("title", "")), "body": scrub(i.get("body", "")),
                                "data": scrub(i.get("data") or {})})  # fmt: skip
    return clean_items, [{**d, "title": scrub(d.get("title") or ""), "text": scrub(d.get("text"))} for d in documents]
