"""Playbooks: the standard steps of an investigation, run for you, in order, inside a case.

An experienced investigator starting on a company does the same things every time: look it up in
the register, find its directors and owners, check each against the sanctions lists and the
leaks, preserve the register page, and write down what stands out. A **playbook** does that from
one starting point (a company name, a person, a username, an email address, a wallet, a website,
a phone number), so nothing is forgotten and every run is recorded the same way.

Each playbook is a short list of steps:

* **scan**: run a set of modules over the starting point (linked to the case, through the case's
  route; an anonymous case only ever uses passive modules);
* **capture**: preserve the pages that matter (the register entry, the profiles found, the
  website's home page) as evidence, with fingerprints and a chain of custody;
* **findings**: pick out what stands out (sanctions matches, leaks, breaches, accounts, directors
  and owners) and write it to the case as a note, plus suggestions the investigator can add;
* **brief**: optionally, have the AI analyst brief the investigator on the case (only when they
  asked for it and confirmed sending the case to Anthropic).

Steps that can't run (a module needs a key, no capture browser) are skipped and say why; one
failing step never stops the others.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from argus.core.graph import IntelligenceGraph
from argus.core.models import EntityType, RelationType

StepKind = Literal["scan", "capture", "findings", "brief"]


@dataclass(frozen=True)
class Step:
    kind: StepKind
    title: str
    modules: tuple[str, ...] = ()
    depth: int = 1
    variants: bool = False  # username targets: also search likely variants
    capture: tuple[str, ...] = ()  # what to capture: "register", "profiles", "website"
    limit: int = 10


@dataclass(frozen=True)
class Playbook:
    id: str
    name: str
    summary: str
    seed_types: tuple[EntityType, ...]
    steps: tuple[Step, ...]
    when: str = ""  # when to use it, for the person choosing

    def as_dict(self, available_modules: set[str] | None = None) -> dict[str, Any]:
        return {
            "id": self.id, "name": self.name, "summary": self.summary, "when": self.when,
            "seed_types": [t.value for t in self.seed_types],
            "steps": [{"kind": s.kind, "title": s.title, "modules": list(s.modules),
                       "unavailable": sorted(set(s.modules) - available_modules) if available_modules is not None else []}
                      for s in self.steps],
        }  # fmt: skip


FINDINGS = Step("findings", "Write down what stands out")
BRIEF = Step("brief", "AI analyst briefing (if you asked for it)")

CATALOGUE: dict[str, Playbook] = {p.id: p for p in (
    Playbook(
        "company_due_diligence", "Company due diligence",
        "Who runs and owns a company, its parent companies, and whether any of them are sanctioned or "
        "named in offshore leaks.",
        (EntityType.ORGANIZATION,),
        (Step("scan", "Registers, owners, sanctions and leaks",
              ("companies_house", "gleif", "sec_edgar", "offshore_leaks", "sanctions_screen"), depth=2),
         Step("capture", "Preserve the register entries", capture=("register",), limit=5),
         FINDINGS, BRIEF),
        when="A company name, e.g. a supplier, a charity's trading arm, or a company in a story.",
    ),
    Playbook(
        "person_background", "Person background",
        "A person's directorships and companies, and whether the name appears on sanctions lists or in "
        "offshore leaks. Matches on a name are only possibilities and are marked as such.",
        (EntityType.PERSON,),
        (Step("scan", "Directorships, sanctions and leaks", ("companies_house", "offshore_leaks", "sanctions_screen")),
         Step("capture", "Preserve the register entries", capture=("register",), limit=5),
         FINDINGS, BRIEF),
        when="A person's full name. Never use it on a child.",
    ),
    Playbook(
        "online_identity", "Online identity",
        "The accounts a username (and its likely variants) has across hundreds of sites, with the public "
        "profile details, and a preserved copy of each profile found.",
        (EntityType.USERNAME,),
        (Step("scan", "Accounts on hundreds of sites", ("username_hunter", "github_hunter", "profile_enricher"),
              variants=True),
         Step("capture", "Preserve the profiles found", capture=("profiles",), limit=10),
         FINDINGS, BRIEF),
        when="A username or handle seen online.",
    ),
    Playbook(
        "email_footprint", "Email footprint",
        "What an email address reveals: its domain, breaches it appears in, published keys, and the "
        "accounts behind its username.",
        (EntityType.EMAIL,),
        (Step("scan", "Domain, breaches, keys and accounts",
              ("email_recon", "hibp", "pgp_keyserver", "username_hunter", "github_hunter", "profile_enricher"), depth=2),
         Step("capture", "Preserve the profiles found", capture=("profiles",), limit=10),
         FINDINGS, BRIEF),
        when="An email address, e.g. from a scam message or a company filing.",
    ),
    Playbook(
        "crypto_trail", "Crypto trail",
        "Where a wallet's money came from and went, the exchanges and services involved, wallets probably "
        "owned by the same person, and any sanctioned counterparties.",
        (EntityType.CRYPTO_WALLET,),
        (Step("scan", "Follow the money", ("bitcoin_wallet", "evm_wallet"), depth=2), FINDINGS, BRIEF),
        when="A Bitcoin or Ethereum-style wallet address, e.g. from a donation page or a ransom note.",
    ),
    Playbook(
        "website_background", "Website background",
        "Who registered a website and when, its history in the Wayback Machine, related domains and "
        "look-alikes. The only visit to the website itself is to preserve its home page, through the case's route.",
        (EntityType.DOMAIN,),
        (Step("scan", "Registration, history and related sites",
              ("whois_lookup", "dns_recon", "passive_dns", "wayback", "subdomain_finder", "infrastructure_pivot",
               "lookalike_domains")),
         Step("capture", "Preserve the home page", capture=("website",), limit=1),
         FINDINGS, BRIEF),
        when="A website, e.g. a fundraising page or a shop that may be fake.",
    ),
    Playbook(
        "phone_lookup", "Phone number",
        "The country, carrier and line type of a phone number, and where it has been published.",
        (EntityType.PHONE,),
        (Step("scan", "Number details", ("phone_recon",)), FINDINGS, BRIEF),
        when="A phone number, with its country code.",
    ),
)}  # fmt: skip

for_type = {t: [p.id for p in CATALOGUE.values() if t in p.seed_types] for t in EntityType}


# ---------------------------------------------------------------------------- what stands out
@dataclass
class Highlight:
    level: Literal["high", "medium", "info"]
    title: str
    detail: str = ""
    entity: dict[str, Any] | None = None  # a suggested case entity: {type, value, attributes}
    url: str | None = None
    tick: bool | None = None  # ticked to add by default (None: when it needs attention or checking)

    def as_dict(self) -> dict[str, Any]:
        tick = self.level != "info" if self.tick is None else self.tick
        return {"level": self.level, "title": self.title, "detail": self.detail, "entity": self.entity, "url": self.url,
                "tick": bool(self.entity) and tick}  # fmt: skip


CASE_TYPES = {
    EntityType.PERSON: "person", EntityType.ORGANIZATION: "organisation", EntityType.USERNAME: "username",
    EntityType.SOCIAL_PROFILE: "account", EntityType.EMAIL: "email", EntityType.PHONE: "phone",
    EntityType.DOMAIN: "domain", EntityType.IP_ADDRESS: "ip", EntityType.LOCATION: "location",
    EntityType.CRYPTO_WALLET: "wallet",
}  # fmt: skip
LEVEL_ORDER = {"high": 0, "medium": 1, "info": 2}


def _suggest(entity: Any, **attributes: Any) -> dict[str, Any] | None:
    case_type = CASE_TYPES.get(entity.type)
    if case_type is None:
        return None
    attrs = {k: str(v)[:500] for k, v in attributes.items() if v not in (None, "", [])}
    return {"type": case_type, "value": entity.value[:500], "attributes": attrs}


def highlights(graph: IntelligenceGraph, *, limit: int = 60) -> list[Highlight]:
    """The findings a person would want to see first, most serious first."""
    out: list[Highlight] = []
    entities = {e.id: e for e in graph.get_all_entities()}
    for e in entities.values():
        md = e.metadata
        for match in md.get("sanction_matches") or []:
            conflicts = match.get("conflicts") or []
            out.append(Highlight(
                "medium" if conflicts else "high",
                f"Possible sanctions match: {e.label or e.value}",
                f"{match.get('name', '?')} on {match.get('list', 'a sanctions list')} (score {match.get('score', 0):.2f})"
                + (f". Probably a different person: {'; '.join(conflicts)}" if conflicts else ""),
                _suggest(e, sanctions=f"{match.get('name')} ({match.get('list')})"),
                tick=not conflicts,  # probably a namesake: not added unless the investigator chooses
            ))  # fmt: skip
        if md.get("sanctions"):
            out.append(Highlight("high", f"Sanctioned wallet: {e.value}", "; ".join(map(str, md["sanctions"]))[:500],
                                 _suggest(e, sanctions="listed")))  # fmt: skip
        for flagged in md.get("sanctioned_counterparties") or []:
            address = flagged.get("address", "?") if isinstance(flagged, dict) else str(flagged)
            listed = f" ({flagged['name']})" if isinstance(flagged, dict) and flagged.get("name") else ""
            out.append(
                Highlight("high", f"Dealt with a sanctioned wallet: {address}{listed}", f"counterparty of {e.value}")
            )
        out.extend(
            Highlight("medium", f"Named in the Offshore Leaks: {e.label or e.value}",
                      f"{hit.get('name')} (score {hit.get('score', 0):.2f}); ICIJ Offshore Leaks Database",
                      _suggest(e, offshore_leaks=hit.get("url")), hit.get("url"))
            for hit in (md.get("offshore_leaks") or [])[:3]
        )  # fmt: skip
        if e.type == EntityType.BREACH:
            out.append(Highlight("medium", f"Appears in a data breach: {e.label or e.value}",
                                 str(md.get("description") or md.get("date") or "")[:300]))  # fmt: skip
        if e.type == EntityType.SOCIAL_PROFILE:
            out.append(Highlight("info", f"Account found: {e.label or e.value}",
                                 f"confidence {e.confidence:.0%}" + (f", {md['name']}" if md.get("name") else ""),
                                 _suggest(e, platform=md.get("platform"), name=md.get("name")), e.value))  # fmt: skip
        if md.get("registry_candidates"):
            names = ", ".join(str(c.get("name")) for c in md["registry_candidates"][:5])
            out.append(Highlight("info", f"No exact register match for {e.value}", f"Closest: {names}"))
        if md.get("officer_matches"):
            out.append(Highlight("info", f"{len(md['officer_matches'])} director(s) with this name",
                                 "; ".join(f"{m.get('name')} (born {m.get('born') or '?'}, {m.get('appointments') or '?'} "
                                           f"appointments)" for m in md["officer_matches"][:5])))  # fmt: skip
    for r in graph.get_all_relations():
        who, what = entities.get(r.source_id), entities.get(r.target_id)
        if who is None or what is None:
            continue
        if r.type == RelationType.SAME_WALLET:
            out.append(Highlight("medium", f"Probably the same owner: {what.value}", f"spent together with {who.value}",
                                 _suggest(what, same_owner_as=who.value)))  # fmt: skip
            continue
        if r.type not in (RelationType.OFFICER_OF, RelationType.CONTROLS):
            continue
        role = r.label or ("controls" if r.type == RelationType.CONTROLS else "officer")
        level: Literal["high", "medium", "info"] = "info"
        out.append(Highlight(level, f"{who.label or who.value}: {role} of {what.label or what.value}",
                             ", ".join(str(x) for x in (r.metadata.get("nature") or [])) if r.metadata else "",
                             _suggest(who, role=f"{role} of {what.value}", born=who.metadata.get("born"),
                                      nationality=who.metadata.get("nationality"))))  # fmt: skip
    seen, unique = set(), []
    for h in sorted(out, key=lambda h: LEVEL_ORDER[h.level]):
        if h.title not in seen:
            seen.add(h.title)
            unique.append(h)
    return unique[:limit]


def capture_urls(graph: IntelligenceGraph, what: tuple[str, ...], seed: str, limit: int) -> list[str]:
    """The pages a capture step preserves."""
    urls: list[str] = []
    entities = graph.get_all_entities()
    if "register" in what:
        for e in sorted(entities, key=lambda e: e.depth):
            urls.extend(str(e.metadata[k]) for k in ("register_url", "lei_url", "sec_url") if e.metadata.get(k))
    if "profiles" in what:
        profiles = [e for e in entities if e.type == EntityType.SOCIAL_PROFILE and e.confidence >= 0.6]
        urls += [e.value for e in sorted(profiles, key=lambda e: -e.confidence) if e.value.startswith("https://")]
    if "website" in what:
        urls.append(f"https://{seed.strip().lower().removeprefix('https://').removeprefix('http://').strip('/')}/")
    return list(dict.fromkeys(urls))[:limit]


def findings_note(name: str, seed: str, found: list[Highlight], stats: dict[str, Any]) -> str:
    """The note a run writes to the case."""
    lines = [f"Playbook: {name}, started from {seed}.",
             f"Found {stats.get('entities', 0)} items and {stats.get('relations', 0)} links."]  # fmt: skip
    labels = {"high": "Needs attention", "medium": "Worth checking", "info": "Also found"}
    for level in ("high", "medium", "info"):
        rows = [h for h in found if h.level == level]
        if rows:
            lines += ["", f"{labels[level]}:", *(f"- {h.title}" + (f": {h.detail}" if h.detail else "") for h in rows)]
    if not found:
        lines += ["", "Nothing stood out. Absence of results is not proof of absence: sources are incomplete."]
    lines += ["", "Written automatically by Argus. Name matches are possibilities, not identifications: check each "
              "against its source before relying on it."]  # fmt: skip
    return "\n".join(lines)
