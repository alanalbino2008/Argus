"""Identity resolution: turn scattered identifiers into people.

A scan finds *fragments* - an email address here, a GitHub account there, a
Keybase profile that proves both belong to the same handle. Analysts care about
the *person* behind them. This module groups linked identity fragments into
**personas** and builds a dossier for each:

* who they appear to be (names, handles, emails, phone numbers),
* where they are present (accounts, with the public profile facts collected),
* what is known about them (declared locations, employers, personal websites),
* what has happened (a timeline of account creation and data breaches),
* why it matters (exposures and the attack paths they take part in).

Grouping uses union-find over relations *between identity entities only*.
Organisations, domains and locations are attributes, never bridges - otherwise
everyone at a company would merge into one "person". Role mailboxes such as
``info@`` or ``security@`` are not people and never bridge either.

Every link is graded, because the same handle on two sites is a lead, not proof:

* ``verified`` - the platform or a cryptographic proof confirms it (Keybase
  proofs, Mastodon ``rel="me"`` links, Gravatar keyed by the email hash);
* ``strong``   - high-confidence collection (e.g. an email published on a profile);
* ``probable`` - the same handle exists elsewhere; could be someone else.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Any

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType

IDENTITY_TYPES = {
    EntityType.PERSON,
    EntityType.USERNAME,
    EntityType.EMAIL,
    EntityType.SOCIAL_PROFILE,
    EntityType.PHONE,
}

# Shared mailboxes: an address like info@ is a team inbox, not a person, and its
# local part ("info") is not a personal handle worth hunting on social networks.
ROLE_MAILBOXES = frozenset(
    {
        "abuse",
        "admin",
        "administrator",
        "billing",
        "contact",
        "careers",
        "dev",
        "dmarc",
        "enquiries",
        "events",
        "feedback",
        "finance",
        "hello",
        "help",
        "hostmaster",
        "hr",
        "info",
        "it",
        "jobs",
        "legal",
        "mail",
        "marketing",
        "media",
        "news",
        "newsletter",
        "no-reply",
        "noreply",
        "office",
        "ops",
        "postmaster",
        "press",
        "privacy",
        "root",
        "sales",
        "security",
        "support",
        "team",
        "webmaster",
    }
)


def is_role_mailbox(value: str) -> bool:
    """True for shared inboxes (``info@acme.com``) and their bare local parts (``info``)."""
    return value.split("@", 1)[0].lower().strip() in ROLE_MAILBOXES


def _is_bridge(entity: Entity) -> bool:
    if entity.type not in IDENTITY_TYPES:
        return False
    return not (entity.type in (EntityType.EMAIL, EntityType.USERNAME) and is_role_mailbox(entity.value))


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def _platform(entity: Entity) -> str:
    return str(entity.metadata.get("platform") or entity.label.split(":", 1)[0].strip() or "Profile")


def _profile_facts(entity: Entity) -> dict[str, Any]:
    md = entity.metadata
    facts = dict(md.get("profile") or {})
    # Gravatar (email_recon) stores its facts under its own keys.
    if md.get("aboutMe") and "bio" not in facts:
        facts["bio"] = md["aboutMe"]
    if md.get("currentLocation") and "location" not in facts:
        facts["location"] = md["currentLocation"]
    if md.get("displayName") and "display_name" not in facts:
        facts["display_name"] = md["displayName"]
    if md.get("avatar_url") and "avatar_url" not in facts:
        facts["avatar_url"] = md["avatar_url"]
    return facts


def _link_grade(entity: Entity) -> str:
    md = entity.metadata
    if md.get("verified") or entity.source_module == "email_recon" or md.get("origin", "").startswith("verified"):
        return "verified"
    if entity.source_module == "username_hunter" and entity.confidence < 0.99:
        return "probable"  # the handle exists there; it may belong to someone else
    return "strong" if entity.confidence >= 0.8 else "probable"


def _persona_id(member_ids: list[str]) -> str:
    return "persona_" + hashlib.sha256("|".join(sorted(member_ids)).encode()).hexdigest()[:12]


def resolve_people(graph: IntelligenceGraph, paths: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Group identity fragments into personas and build a dossier for each."""
    entities = {e.id: e for e in graph.get_all_entities()}
    adjacency: dict[str, set[str]] = defaultdict(set)
    uf = _UnionFind()
    for rel in graph.get_all_relations():
        a, b = entities.get(rel.source_id), entities.get(rel.target_id)
        if a is None or b is None:
            continue
        adjacency[a.id].add(b.id)
        adjacency[b.id].add(a.id)
        if _is_bridge(a) and _is_bridge(b):
            uf.union(a.id, b.id)

    groups: dict[str, list[Entity]] = defaultdict(list)
    for entity in entities.values():
        if _is_bridge(entity):
            groups[uf.find(entity.id)].append(entity)

    personas = [_dossier(members, entities, adjacency, paths or []) for members in groups.values()]
    # A lone handle that led nowhere is noise; keep everything else.
    personas = [p for p in personas if p["summary"]["fragments"] > 1 or not p["lone_username"]]
    for p in personas:
        del p["lone_username"]
    personas.sort(key=lambda p: (-p["risk"], -p["summary"]["fragments"], p["name"].lower()))

    role_mailboxes = sorted(
        e.value for e in entities.values() if e.type == EntityType.EMAIL and is_role_mailbox(e.value)
    )
    return {
        "personas": personas,
        "role_mailboxes": role_mailboxes,
        "summary": {
            "personas": len(personas),
            "accounts": sum(len(p["accounts"]) for p in personas),
            "exposed": sum(1 for p in personas if p["exposures"]),
        },
    }


def _dossier(
    members: list[Entity],
    entities: dict[str, Entity],
    adjacency: dict[str, set[str]],
    paths: list[dict[str, Any]],
) -> dict[str, Any]:
    by_type: dict[EntityType, list[Entity]] = defaultdict(list)
    for m in sorted(members, key=lambda e: (-e.confidence, e.value.lower())):
        by_type[m.type].append(m)
    member_ids = {m.id for m in members}

    def neighbours(of: list[Entity], etype: EntityType) -> list[Entity]:
        found = {n for m in of for n in adjacency.get(m.id, ()) if entities[n].type == etype}
        return sorted((entities[n] for n in found), key=lambda e: e.value.lower())

    accounts: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []
    for profile in by_type[EntityType.SOCIAL_PROFILE]:
        facts = _profile_facts(profile)
        platform = _platform(profile)
        accounts.append(
            {
                "entity_id": profile.id,
                "platform": platform,
                "url": profile.value if profile.value.startswith(("http://", "https://")) else None,
                "handle": profile.metadata.get("username") or profile.metadata.get("handle"),
                "link": _link_grade(profile),
                "confidence": round(profile.confidence, 2),
                "facts": facts,
            }
        )
        if facts.get("created_at"):
            timeline.append(
                {"date": str(facts["created_at"])[:10], "event": f"Joined {platform}", "entity_id": profile.id}
            )

    emails = by_type[EntityType.EMAIL]
    breaches = neighbours(emails, EntityType.BREACH)
    breach_rows: list[dict[str, Any]] = []
    for b in breaches:
        classes = list(b.metadata.get("data_classes") or [])
        breach_rows.append(
            {"entity_id": b.id, "name": b.value, "date": b.metadata.get("breach_date"), "data_classes": classes}
        )
        if b.metadata.get("breach_date"):
            timeline.append(
                {
                    "date": str(b.metadata["breach_date"])[:10],
                    "event": f"Data exposed in {b.value} breach",
                    "entity_id": b.id,
                }
            )
    timeline.sort(key=lambda t: (t["date"], t["event"]))

    locations = neighbours(members, EntityType.LOCATION)
    organisations = neighbours(members, EntityType.ORGANIZATION)
    websites = [d for d in neighbours(by_type[EntityType.SOCIAL_PROFILE], EntityType.DOMAIN) if d.depth > 0]

    names = [p.value for p in by_type[EntityType.PERSON]]
    display_names = [a["facts"]["display_name"] for a in accounts if a["facts"].get("display_name")]
    usernames = [u.value for u in by_type[EntityType.USERNAME]]
    handles = sorted({a["handle"] for a in accounts if a["handle"]} | set(usernames), key=str.lower)
    name = (
        names[0]
        if names
        else display_names[0]
        if display_names
        else handles[0]
        if handles
        else emails[0].value
        if emails
        else members[0].label
    )

    exposures: list[dict[str, str]] = []
    risk = 0
    for row in breach_rows:
        pw = any("password" in c.lower() for c in row["data_classes"])
        exposures.append(
            {
                "severity": "high" if pw else "medium",
                "text": f"{'Password' if pw else 'Personal data'} exposed in the {row['name']} breach",
            }
        )
        risk += 30 if pw else 15
    if locations:
        exposures.append(
            {"severity": "medium", "text": f"Location published: {', '.join(loc.value for loc in locations[:2])}"}
        )
        risk += 10
    public_emails = [e for e in emails if e.metadata.get("origin") == "published on profile"]
    if public_emails:
        exposures.append({"severity": "medium", "text": "Email address published on a public profile"})
        risk += 10
    if organisations and (emails or accounts):
        exposures.append(
            {
                "severity": "low",
                "text": f"Employer is public ({organisations[0].value}): enables targeted phishing pretexts",
            }
        )
        risk += 5
    if len(accounts) >= 3:
        exposures.append(
            {"severity": "low", "text": f"Present on {len(accounts)} platforms: a large social-engineering surface"}
        )
        risk += 5
    if by_type[EntityType.PHONE]:
        exposures.append({"severity": "medium", "text": "Phone number is public (SIM-swap and vishing risk)"})
        risk += 10

    # Shared inboxes they are listed against (e.g. a WHOIS contact): context, not identity.
    mailboxes = sorted(
        {entities[n].value for m in members for n in adjacency.get(m.id, ()) if entities[n].type == EntityType.EMAIL}
        - {e.value for e in emails}
    )
    attribute_ids = {e.id for e in (*breaches, *locations, *organisations, *websites)}
    related_paths = [
        {"id": p["id"], "title": p["title"], "severity": p["severity"], "score": p["score"]}
        for p in paths
        if member_ids & {s["entity_id"] for s in p.get("steps", [])}
    ]
    risk += sum(10 for p in related_paths if p["severity"] in ("critical", "high"))

    grades = {a["link"] for a in accounts}
    strength = "verified" if "verified" in grades else "strong" if "strong" in grades or names else "probable"

    return {
        "id": _persona_id(sorted(member_ids)),
        "name": name,
        "strength": strength,
        "risk": min(risk, 100),
        "avatar_url": next((a["facts"]["avatar_url"] for a in accounts if a["facts"].get("avatar_url")), None),
        "bio": next((a["facts"]["bio"] for a in accounts if a["facts"].get("bio")), None),
        "names": sorted(set(names) | set(display_names)),
        "usernames": handles,
        "emails": [e.value for e in emails],
        "phones": [p.value for p in by_type[EntityType.PHONE]],
        "accounts": accounts,
        "locations": [loc.value for loc in locations],
        "organisations": [o.value for o in organisations],
        "websites": [w.value for w in websites],
        "shared_mailboxes": mailboxes,
        "breaches": breach_rows,
        "timeline": timeline,
        "exposures": exposures,
        "attack_paths": related_paths,
        "entity_ids": sorted(member_ids | attribute_ids),
        "summary": {"fragments": len(members), "accounts": len(accounts), "breaches": len(breach_rows)},
        "lone_username": len(members) == 1 and members[0].type == EntityType.USERNAME,
    }
