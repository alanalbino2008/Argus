"""What goes into a client report: plain data, computed once, rendered by ``pdf.py``.

Keeping content separate from layout makes the report testable without parsing a PDF, and
keeps the decisions explicit:

* **Personal data is minimised.** People are summarised (counts, the email-address format,
  role mailboxes) rather than listed, and wherever an attack path mentions a person their
  identifiers are **pseudonymised**: "Person A", ``d•••@acme.com``, a phone number's last two
  digits. Labels stay consistent within a report, so paths still read correctly. A report is
  a document that gets forwarded; GDPR's data-minimisation principle says it should carry no
  more personal data than its purpose needs. When the client must act on specific accounts,
  an analyst can opt in to full detail (recorded in the audit log).
* **Rule-based findings are labelled as assessments**, not confirmed exploitation.
* Every value that came from the internet is treated as untrusted text by the renderer.
"""

from __future__ import annotations

import copy
import re
import secrets
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

from argus.core.graph import IntelligenceGraph
from argus.core.models import Investigation
from argus.intel.attack import map_investigation
from argus.intel.diff import compare
from argus.intel.identity import resolve_people
from argus.intel.paths import find_attack_paths
from argus.intel.rating import compute_rating
from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer

Tlp = Literal["CLEAR", "GREEN", "AMBER", "AMBER+STRICT", "RED"]
SEVERITIES = ("critical", "high", "medium", "low")

TLP_MEANING = {
    "CLEAR": "Disclosure is not limited.",
    "GREEN": "Limited disclosure: the recipient may share it within their community, but not publicly.",
    "AMBER": "Limited disclosure: the recipient may share it within their organisation and with its "
    "clients on a need-to-know basis.",
    "AMBER+STRICT": "Limited disclosure: the recipient may share it only within their own organisation.",
    "RED": "For the eyes and ears of the named recipients only: no further disclosure.",
}

CATEGORY_LABELS = {
    "domain": "Domains",
    "subdomain": "Subdomains",
    "ip_address": "IP addresses",
    "asn": "Networks (ASN)",
    "certificate": "TLS certificates",
    "technology": "Technologies",
    "dns_record": "DNS records",
    "port": "Exposed services",
    "vulnerability": "Vulnerabilities",
    "url": "URLs",
    "organization": "Organisations",
    "breach": "Data breaches",
    "generic": "Other",
}
# Never listed individually in a client report (see the module docstring).
PERSONAL_TYPES = {"email", "username", "social_profile", "person", "phone", "location"}
MAX_INVENTORY_ROWS = 300
MAX_PATHS = 25


@dataclass
class Branding:
    organisation: str = "Argus"
    accent: str = "#4f46e5"
    logo_png: bytes | None = None
    footer_note: str = ""


@dataclass
class ReportOptions:
    prepared_for: str = ""
    tlp: Tlp = "AMBER"
    include_inventory: bool = True
    compare_previous: bool = True
    include_personal_details: bool = False


@dataclass
class ReportData:
    report_id: str
    generated_at: datetime
    target: str
    options: ReportOptions
    branding: Branding
    investigation: dict[str, Any]
    rating: str
    score: int
    counts: dict[str, int]
    severity_counts: dict[str, int]
    summary: list[str]
    recommendations: list[dict[str, Any]]
    paths: list[dict[str, Any]]
    paths_total: int
    flags: list[str]
    categories: list[dict[str, Any]]
    inventory: list[dict[str, str]]
    inventory_truncated: int
    techniques: list[dict[str, Any]]
    people: dict[str, Any]
    trend: dict[str, Any] | None
    sources: list[dict[str, Any]]
    generator: str = ""
    lookalikes: list[dict[str, Any]] = field(default_factory=list)
    related: list[dict[str, Any]] = field(default_factory=list)
    security_rating: dict[str, Any] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)


def new_report_id() -> str:
    return f"ARG-{secrets.token_hex(4).upper()}"


def overall_rating(severity_counts: dict[str, int]) -> str:
    for severity in SEVERITIES:
        if severity_counts.get(severity):
            return severity
    return "minimal"


def _date(value: datetime | None) -> str:
    return value.strftime("%d %B %Y") if value else "—"


def _recommendations(paths: list[dict[str, Any]], limit: int = 8) -> list[dict[str, Any]]:
    """The first fix of each path, most urgent first, merged when several paths share it."""
    merged: dict[str, dict[str, Any]] = {}
    for path in paths:  # already ordered by score
        if not path.get("remediation"):
            continue
        action = path["remediation"][0]
        item = merged.setdefault(action, {"action": action, "severity": path["severity"], "paths": []})
        item["paths"].append(path["title"])
    return list(merged.values())[:limit]


def _mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    return f"{local[:1]}•••@{domain}" if domain else f"{value[:1]}•••"


def pseudonymiser(graph: IntelligenceGraph) -> Callable[[str], str]:
    """A function that replaces every personal identifier in the graph with a stable pseudonym."""
    entities = graph.get_all_entities()
    mapping: dict[str, str] = {}
    people = sorted({e.label for e in entities if e.type.value == "person"} | {
        str(n) for e in entities if e.type.value == "person" for n in (e.metadata.get("names") or [])
    })  # fmt: skip
    for i, name in enumerate(people):
        mapping[name] = f"Person {chr(65 + i) if i < 26 else i + 1}"
    for e in entities:
        kind = e.type.value
        for raw in {e.label, e.value}:
            value = str(raw or "").strip()
            if len(value) < 3 or value in mapping:
                continue
            if kind == "email":
                mapping[value] = _mask_email(value)
            elif kind == "username":
                mapping[value] = f"{value[:1]}•••"
            elif kind == "phone":
                digits = re.sub(r"\D", "", value)
                mapping[value] = f"•••{digits[-2:]}" if digits else "•••"
            elif kind == "location":
                mapping[value] = "[location]"
    if not mapping:
        return lambda text: text
    keys = sorted(mapping, key=len, reverse=True)  # longest first: an email before the username inside it
    pattern = re.compile("|".join(rf"(?<![\w]){re.escape(k)}(?![\w])" for k in keys), re.IGNORECASE)
    lowered = {k.lower(): v for k, v in mapping.items()}
    return lambda text: pattern.sub(lambda m: lowered.get(m.group(0).lower(), m.group(0)), text)


def _redact_path(path: dict[str, Any], redact: Callable[[str], str]) -> dict[str, Any]:
    out = copy.deepcopy(path)
    for key in ("title", "narrative"):
        if isinstance(out.get(key), str):
            out[key] = redact(out[key])
    for key in ("evidence", "remediation"):
        out[key] = [redact(str(x)) for x in out.get(key) or []]
    for step in out.get("steps") or []:
        step["label"] = redact(str(step.get("label", "")))
    return out


def _rating_for_report(rating: dict[str, Any], redact: Callable[[str], str]) -> dict[str, Any]:
    """The rating, with issue titles pseudonymised like the rest of the report."""
    titles = {i["id"]: redact(i["title"]) for i in rating["issues"]}
    return {
        **{k: rating[k] for k in ("score", "grade", "confidence", "provisional", "critical_issues", "capped_at",
                                  "uncapped_score", "methodology")},
        "factors": rating["factors"],
        "plan": [{"title": titles[i], "fix": next(x["fix"] for x in rating["issues"] if x["id"] == i)}
                 for i in rating["plan"]["issues"]],
        "plan_reaches": rating["plan"]["reaches"],
    }  # fmt: skip


def build_report_data(
    investigation: Investigation,
    graph: IntelligenceGraph,
    options: ReportOptions,
    branding: Branding,
    *,
    previous: tuple[Investigation, IntelligenceGraph] | None = None,
    generator: str = "Argus",
) -> ReportData:
    analytics = GraphIntelligenceAnalyzer.analyze(graph)
    found = find_attack_paths(graph)
    redact = (lambda text: text) if options.include_personal_details else pseudonymiser(graph)
    paths: list[dict[str, Any]] = [_redact_path(p, redact) for p in found["paths"]]
    severity_counts = {s: int(found["summary"]["by_severity"].get(s, 0)) for s in SEVERITIES}
    rating = overall_rating(severity_counts)
    entities = graph.get_all_entities()

    by_type: dict[str, list[Any]] = {}
    for entity in entities:
        if entity.metadata.get("out_of_scope"):
            continue  # third parties' assets (e.g. lookalike domains) are not the target's attack surface
        by_type.setdefault(entity.type.value, []).append(entity)
    listed = sorted((t for t in by_type if t not in PERSONAL_TYPES), key=lambda t: (-len(by_type[t]), t))
    categories: list[dict[str, Any]] = [
        {"type": t, "label": CATEGORY_LABELS.get(t, t.replace("_", " ").title()), "count": len(by_type[t])}
        for t in listed
    ]
    inventory_rows = [
        {"category": CATEGORY_LABELS.get(t, t), "value": e.label, "source": e.source_module}
        for t in listed
        for e in sorted(by_type[t], key=lambda e: e.label)
    ]

    people = resolve_people(graph, found["paths"])
    people_summary = {
        "people": people["summary"].get("personas", 0),
        "linked_accounts": people["summary"].get("accounts", 0),
        "exposed": people["summary"].get("exposed", 0),
        "role_mailboxes": list(people.get("role_mailboxes") or [])[:10],
        "email_format": (people.get("email_format") or {}).get("example"),
        "personal_items": sum(len(by_type.get(t, [])) for t in PERSONAL_TYPES),
    }

    trend = None
    if previous is not None:
        prev_inv, prev_graph = previous
        diff = compare(prev_graph, graph)
        trend = {
            "previous_date": _date(prev_inv.completed_at),
            **{k: diff["summary"][k] for k in ("added", "removed", "new_paths", "resolved_paths", "escalated_paths")},
            "risk_delta": diff["summary"]["risk_delta"],
            "trend": diff["summary"]["trend"],
        }

    target = investigation.config.target
    total = len(paths)
    summary = [
        f"Argus assessed the publicly discoverable attack surface of {target} on "
        f"{_date(investigation.completed_at or investigation.created_at)}. It identified {len(entities)} assets and "
        f"{analytics['edge_count']} relationships between them, and chained the findings into {total} plausible "
        f"attack path{'' if total == 1 else 's'}.",
    ]
    if total:
        worst = paths[0]
        breakdown = ", ".join(f"{severity_counts[s]} {s}" for s in SEVERITIES if severity_counts[s])
        summary.append(
            f"Overall exposure is rated {rating.upper()} ({breakdown}). The most urgent issue is: {worst['title']}."
        )
    else:
        summary.append("No attack paths were identified; overall exposure is rated MINIMAL.")
    if trend:
        direction = {"worse": "increased", "better": "decreased", "unchanged": "did not change"}[trend["trend"]]
        summary.append(
            f"Compared with the assessment of {trend['previous_date']}, risk {direction} "
            f"({trend['risk_delta']:+d}): {trend['new_paths']} new and {trend['resolved_paths']} resolved attack "
            f"path(s), {trend['added']} new asset(s)."
        )
    if people_summary["people"]:
        summary.append(
            f"{people_summary['people']} staff member(s) are publicly identifiable"
            + (
                f" and the email address format ({people_summary['email_format']}) can be inferred, which makes "
                "targeted phishing easier."
                if people_summary["email_format"]
                else "."
            )
        )

    stats = investigation.module_stats or {}
    produced = Counter(e.source_module for e in entities)
    sources = [
        {"module": name, "findings": produced.get(name, 0), "status": (stats.get(name) or {}).get("status", "ran")}
        for name in sorted(set(produced) | set(stats))
        if name != "seed"
    ]

    attack = map_investigation(graph)
    return ReportData(
        report_id=new_report_id(),
        generated_at=datetime.now(timezone.utc),
        target=target,
        options=options,
        branding=branding,
        investigation={
            "id": investigation.id,
            "purpose": investigation.purpose,
            "created_by": investigation.created_by,
            "scanned": _date(investigation.completed_at or investigation.created_at),
            "depth": investigation.config.max_depth,
            "passive_only": investigation.config.passive_only,
        },
        rating=rating,
        score=int(analytics.get("threat_exposure_score") or 0),
        counts={"assets": len(entities), "relations": int(analytics["edge_count"]), "paths": total},
        severity_counts=severity_counts,
        summary=[redact(line) for line in summary],
        recommendations=_recommendations(paths),
        paths=paths[:MAX_PATHS],
        paths_total=total,
        flags=[redact(str(f)) for f in (analytics.get("risk_flags") or [])[:20]],
        categories=categories,
        inventory=inventory_rows[:MAX_INVENTORY_ROWS] if options.include_inventory else [],
        inventory_truncated=max(0, len(inventory_rows) - MAX_INVENTORY_ROWS) if options.include_inventory else 0,
        techniques=[
            {"id": t["id"], "name": t["name"], "count": t["count"], "defence": t.get("defence", "")}
            for t in attack["techniques"]
        ],
        people=people_summary,
        trend=trend,
        sources=sources,
        generator=generator,
        lookalikes=[
            {
                "display": redact(str(e.metadata["lookalike"].get("display") or e.value)),
                "domain": e.value,
                "detail": e.metadata["lookalike"].get("detail", ""),
                "verdict": e.metadata["lookalike"].get("verdict", ""),
                "mx": bool(e.metadata["lookalike"].get("mx")),
                "risk": int(e.metadata["lookalike"].get("risk", 0)),
            }
            for e in sorted(
                (e for e in entities if e.metadata.get("lookalike")), key=lambda e: -e.metadata["lookalike"]["risk"]
            )
        ][:15],
        security_rating=_rating_for_report(compute_rating(graph, found["paths"]), redact),
        related=[
            {
                "domain": e.value,
                "confidence": float(e.metadata["pivot"].get("confidence", 0)),
                "attribution": e.metadata["pivot"].get("attribution", ""),
                "evidence": [redact(str(x.get("detail", ""))) for x in e.metadata["pivot"].get("evidence", [])][:3],
            }
            for e in sorted(
                (e for e in entities if e.metadata.get("pivot")),
                key=lambda e: -e.metadata["pivot"].get("confidence", 0),
            )
        ][:15],
    )
