"""Security rating: one A-F grade from everything a scan found, with a transparent breakdown.

Commercial ratings (SecurityScorecard, BitSight) are widely used by buyers, insurers and
supply-chain teams, and widely criticised as black boxes. This one is built to be explained:

* **Eight factors**, each scored 0-100, combined with published weights.
* Every point lost is an **issue** with its evidence and its fix. Most issues are the curated
  attack paths; a few are direct measurements (DMARC policy, SPF strictness, security
  headers, security.txt, certificate expiry).
* **Diminishing returns** inside a factor: the second open database matters, but less than the
  first. A factor never goes below 0.
* **Critical findings cap the grade**: an actively exploited vulnerability is not offset by
  good email hygiene. One critical issue caps the score at 69 (D), three or more at 59 (F).
* **Coverage is explicit**: a factor without data (e.g. web and TLS in a passive-only scan) is
  *not assessed*, left out of the average, and lowers the rating's **confidence** instead of
  pretending to be 100.
* **What-if**: each issue reports the points regained if it were fixed, and the shortest list
  of fixes that reaches the next grade.

``METHODOLOGY_VERSION`` changes whenever weights or rules change, so stored ratings computed
under an older methodology are recomputed rather than compared with newer ones.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType

METHODOLOGY_VERSION = "2026.11-1"
GRADES = (("A", 90), ("B", 80), ("C", 70), ("D", 60), ("F", 0))
SEVERITY_POINTS = {"critical": 35, "high": 20, "medium": 10, "low": 4}
DIMINISHING = (1.0, 0.6, 0.4, 0.3, 0.2)
CAPS = ((3, 59), (1, 69))  # (critical issues at least, maximum score)
PROVISIONAL_BELOW = 0.6  # confidence under which a grade is shown as provisional

FACTORS: dict[str, tuple[str, float, str]] = {
    # id: (name, weight, what it covers)
    "patching": (
        "Vulnerabilities & patching",
        0.20,
        "Known and actively exploited vulnerabilities, unsupported software",
    ),
    "leaks": ("Leaks & data exposure", 0.18, "Breached credentials, secrets in public code, exposed files and storage"),
    "network": ("Network exposure", 0.15, "Risky services reachable from the internet"),
    "web": ("Web & TLS", 0.12, "Browser security headers, certificates, information leaks"),
    "email": ("Email security", 0.10, "Spoofing protection: DMARC and SPF"),
    "brand": ("Brand & reputation", 0.10, "Impostor domains, impersonation campaigns, malicious reputation"),
    "dns": ("DNS health", 0.08, "Dangling records that allow subdomain takeover"),
    "social": (
        "Social engineering",
        0.07,
        "Publicly identifiable staff and the information attackers need to phish them",
    ),
}
RULE_FACTOR = {
    "exploitable_public_service": "patching",
    "end_of_life_software": "patching",
    "exposed_sensitive_service": "network",
    "credential_exposure": "leaks",
    "leaked_secret_in_code": "leaks",
    "exposed_sensitive_file": "leaks",
    "public_cloud_storage": "leaks",
    "spoofable_email_domain": "email",
    "tls_interception": "web",
    "web_information_leak": "web",
    "subdomain_takeover_candidate": "dns",
    "identity_correlation": "social",
    "staff_enumeration": "social",
    "malicious_reputation": "brand",
    "lookalike_domain": "brand",
    "lookalike_domain_watchlist": "brand",
    "impostor_campaign": "brand",
}


@dataclass
class Issue:
    id: str
    factor: str
    title: str
    severity: str
    fix: str
    source: str  # "attack_path" or "measurement"
    path_id: str | None = None
    points: float = 0.0  # what it costs within its factor, after diminishing returns
    impact: float = 0.0  # what it costs the overall score before caps (its share of the weighted average)
    gain: float = 0.0  # change in the actual (capped) score if this alone were fixed


@dataclass
class Factor:
    id: str
    name: str
    weight: float
    description: str
    assessed: bool
    score: float = 100.0
    issues: list[Issue] = field(default_factory=list)
    strengths: list[str] = field(default_factory=list)

    @property
    def grade(self) -> str | None:
        return grade_for(self.score) if self.assessed else None


def grade_for(score: float) -> str:
    return next(g for g, floor in GRADES if score >= floor)


# ---------------------------------------------------------------------------- evidence
def _assessed(graph: IntelligenceGraph, seed: Entity | None) -> dict[str, bool]:
    entities = [e for e in graph.get_all_entities() if not e.metadata.get("out_of_scope")]
    types = {e.type for e in entities}
    modules = {e.source_module for e in entities} | {
        s for e in entities for s in (e.metadata.get("sources") or []) if isinstance(s, str)
    }
    md = seed.metadata if seed else {}
    is_domain = bool(seed and seed.type in (EntityType.DOMAIN, EntityType.SUBDOMAIN))
    return {
        "patching": bool(types & {EntityType.PORT, EntityType.VULNERABILITY, EntityType.TECHNOLOGY}),
        "network": EntityType.IP_ADDRESS in types,
        "leaks": bool(
            md.get("wayback")
            or md.get("public_code")
            or md.get("cloud_storage")
            or types & {EntityType.BREACH, EntityType.URL}
            or modules & {"hibp", "code_leaks", "web_recon"}
        ),
        "web": any("security_headers_grade" in e.metadata for e in entities) or EntityType.CERTIFICATE in types,
        "email": bool(md.get("dns_checked")),
        "brand": "lookalikes_checked" in md or "lookalike_domains" in modules,
        "dns": bool(md.get("dns_checked")) or EntityType.SUBDOMAIN in types,
        "social": is_domain,
    }


def _measurements(
    graph: IntelligenceGraph, seed: Entity | None, rules: set[str]
) -> list[tuple[Issue | None, str, str]]:
    """Direct observations: (issue or None, factor, strength text when good)."""
    out: list[tuple[Issue | None, str, str]] = []
    md = seed.metadata if seed else {}
    if md.get("dns_checked"):
        dmarc = md.get("dmarc_policy")
        if dmarc == "reject":
            out.append((None, "email", "DMARC policy is p=reject: forged mail is refused"))
        elif dmarc == "quarantine":
            out.append((Issue("m:dmarc-quarantine", "email", "DMARC quarantines rather than rejects forged mail", "low",
                              "Move DMARC from p=quarantine to p=reject once reports show legitimate mail passes.",
                              "measurement"), "email", ""))  # fmt: skip
        spf = str(md.get("spf") or "")
        if spf.endswith("-all"):
            out.append((None, "email", "SPF hard-fails unauthorised senders (-all)"))
        elif spf.endswith("~all") and "spoofable_email_domain" not in rules:
            out.append((Issue("m:spf-softfail", "email", "SPF only soft-fails unauthorised senders (~all)", "low",
                              "End the SPF record with -all once every legitimate sender is listed.", "measurement"),
                        "email", ""))  # fmt: skip
        elif spf in ("missing", "") and "spoofable_email_domain" not in rules:
            out.append((Issue("m:spf-missing", "email", "No SPF record", "medium",
                              "Publish an SPF record listing your mail senders, ending in -all.", "measurement"),
                        "email", ""))  # fmt: skip
        elif spf.endswith(("+all", "?all")):
            out.append((Issue("m:spf-open", "email", "SPF allows any sender (+all/?all)", "high",
                              "Replace +all/?all with -all: the record currently authorises everyone.", "measurement"),
                        "email", ""))  # fmt: skip
    headers = {"C": "low", "D": "medium", "E": "medium", "F": "medium"}
    graded = [
        e
        for e in graph.get_all_entities()
        if "security_headers_grade" in e.metadata and not e.metadata.get("out_of_scope")
    ]
    for e in sorted(graded, key=lambda e: e.value)[:3]:
        grade = str(e.metadata["security_headers_grade"]).upper()[:1]
        if grade in headers:
            missing = ", ".join((e.metadata.get("missing_security_headers") or [])[:4])
            out.append((Issue(f"m:headers:{e.value}", "web", f"Weak browser security headers on {e.value} (grade {grade})",
                              headers[grade], f"Add the missing headers ({missing or 'see the scan'}).", "measurement"),
                        "web", ""))  # fmt: skip
        elif grade in ("A", "B"):
            out.append((None, "web", f"Strong browser security headers on {e.value} (grade {grade})"))
    security_txt = md.get("security_txt")
    if isinstance(security_txt, dict):
        if security_txt.get("present"):
            out.append((None, "web", "security.txt tells researchers how to report vulnerabilities"))
        else:
            out.append((Issue("m:security-txt", "web", "No security.txt", "low",
                              "Publish /.well-known/security.txt with a contact for vulnerability reports (RFC 9116).",
                              "measurement"), "web", ""))  # fmt: skip
    for cert in graph.get_all_entities():
        if cert.type != EntityType.CERTIFICATE or cert.metadata.get("out_of_scope") or "tls_interception" in rules:
            continue
        days = cert.metadata.get("days_remaining")
        if cert.metadata.get("expired"):
            out.append((Issue(f"m:cert-expired:{cert.value}", "web", f"Expired certificate: {cert.label}", "high",
                              "Renew the certificate and automate renewal (ACME).", "measurement"), "web", ""))  # fmt: skip
        elif isinstance(days, int | float) and days < 14:
            out.append((Issue(f"m:cert-expiring:{cert.value}", "web", f"Certificate expires in {int(days)} day(s)", "low",
                              "Renew now and automate renewal (ACME).", "measurement"), "web", ""))  # fmt: skip
    ports = [e for e in graph.get_all_entities() if e.type == EntityType.PORT and not e.metadata.get("out_of_scope")]
    if len(ports) > 10:
        out.append((Issue("m:many-ports", "network", f"{len(ports)} services exposed to the internet", "low",
                          "Review every exposed service; close what is not meant to be public.", "measurement"),
                    "network", ""))  # fmt: skip
    return out


# ---------------------------------------------------------------------------- scoring
def _score(
    factors: dict[str, Factor], excluded: set[str] | frozenset[str] = frozenset(), *, capped: bool = True
) -> tuple[float, int]:
    """(overall score, critical issue count), ignoring issues whose id is in ``excluded``."""
    total = weight = 0.0
    critical = 0
    for f in factors.values():
        if not f.assessed:
            continue
        live = sorted((i for i in f.issues if i.id not in excluded), key=lambda i: -SEVERITY_POINTS[i.severity])
        lost = sum(SEVERITY_POINTS[i.severity] * DIMINISHING[min(n, len(DIMINISHING) - 1)] for n, i in enumerate(live))
        total += max(0.0, 100.0 - lost) * f.weight
        weight += f.weight
        critical += sum(1 for i in live if i.severity == "critical")
    score = total / weight if weight else 0.0
    for at_least, cap in CAPS if capped else ():
        if critical >= at_least:
            score = min(score, cap)
            break
    return round(score, 1), critical


def compute_rating(graph: IntelligenceGraph, paths: list[dict[str, Any]]) -> dict[str, Any]:
    seed = next((e for e in graph.get_all_entities() if e.depth == 0), None)
    assessed = _assessed(graph, seed)
    factors = {fid: Factor(fid, name, w, desc, assessed[fid]) for fid, (name, w, desc) in FACTORS.items()}
    rules = {p["rule"] for p in paths}
    for p in paths:
        fid = RULE_FACTOR.get(p["rule"])
        if fid:
            factors[fid].assessed = True  # a finding is itself evidence the factor was examined
            factors[fid].issues.append(Issue(
                f"path:{p['id']}", fid, p["title"], p["severity"], (p.get("remediation") or ["See the attack path."])[0],
                "attack_path", path_id=p["id"],
            ))  # fmt: skip
    for issue, fid, strength in _measurements(graph, seed, rules):
        if issue:
            factors[fid].issues.append(issue)
        elif strength:
            factors[fid].strengths.append(strength)

    # Per-factor scores and each issue's cost inside its factor.
    for f in factors.values():
        f.issues.sort(key=lambda i: (-SEVERITY_POINTS[i.severity], i.title))
        for n, issue in enumerate(f.issues):
            issue.points = round(SEVERITY_POINTS[issue.severity] * DIMINISHING[min(n, len(DIMINISHING) - 1)], 1)
        f.score = round(max(0.0, 100.0 - sum(i.points for i in f.issues)), 1) if f.assessed else 100.0

    score, critical = _score(factors)
    uncapped = _score(factors, capped=False)[0]
    issues = [i for f in factors.values() if f.assessed for i in f.issues]
    for issue in issues:
        issue.impact = round(_score(factors, {issue.id}, capped=False)[0] - uncapped, 1)
        issue.gain = round(_score(factors, {issue.id})[0] - score, 1)
    # Critical issues first (they are what caps the grade), then by what they cost.
    issues.sort(key=lambda i: (-SEVERITY_POINTS[i.severity], -i.impact, i.title))

    # The shortest list of fixes, in that order, that reaches the next grade.
    grade = grade_for(score)
    plan: list[str] = []
    if grade != "A":
        target = next(floor for g, floor in reversed(GRADES) if floor > score)
        excluded: set[str] = set()
        for issue in issues:
            excluded.add(issue.id)
            plan.append(issue.id)
            if _score(factors, excluded)[0] >= target:
                break
        else:
            plan = []
        plan_grade = grade_for(_score(factors, set(plan))[0]) if plan else grade
    else:
        plan_grade = grade

    confidence = round(sum(f.weight for f in factors.values() if f.assessed), 2)
    capped_by = next((cap for at_least, cap in CAPS if critical >= at_least), None)
    return {
        "methodology": METHODOLOGY_VERSION,
        "score": score,
        "grade": grade,
        "confidence": confidence,
        "provisional": confidence < PROVISIONAL_BELOW,
        "uncapped_score": uncapped,
        "critical_issues": critical,
        "capped_at": capped_by,
        "factors": [
            {**{k: v for k, v in asdict(f).items() if k != "issues"}, "grade": f.grade, "issue_count": len(f.issues)}
            for f in sorted(factors.values(), key=lambda f: -f.weight)
        ],
        "issues": [asdict(i) for i in issues],
        "plan": {"issues": plan, "reaches": plan_grade},
    }
