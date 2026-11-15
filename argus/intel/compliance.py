"""Compliance mapping: what Argus's evidence says about controls in common frameworks.

Argus sees an organisation **from the outside**, as an attacker would. That is real, independent
evidence for some controls (are admin interfaces exposed? is unsupported software reachable?
are suppliers monitored?) and none at all for others (are laptops encrypted?). This module
says which is which, honestly:

* **coverage**: ``direct`` when outside-in evidence can show the control failing or holding;
  ``partial`` when it supports the control but cannot prove it; ``process`` when the evidence is
  how the organisation *runs* security (monitoring, deadlines, supplier reviews) in Argus.
* **status**: ``gap`` (evidence the control is not met), ``partial`` (met in part, or gaps that
  are already owned and on a deadline), ``met`` (assessed, nothing found), or ``not_assessed``
  (no evidence either way: never reported as a pass).

Each control is judged from:
* the open attack paths of the kinds that would breach it;
* exposure findings;
* supplier status;
* named process checks.

Each status carries the reasons and the evidence behind it. **This supports an audit; it is not
a certification.** Control titles and objectives are paraphrased in Argus's own words. Refer to
the official texts for the exact requirements.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
STATUS_RANK = {"gap": 3, "partial": 2, "met": 1, "not_assessed": 0}
FRESH = timedelta(days=90)  # evidence older than this is stale
CE_PATCH_DAYS = 14  # Cyber Essentials: high and critical updates within 14 days of release


@dataclass(frozen=True)
class Control:
    ref: str
    title: str
    objective: str
    coverage: str  # direct | partial | process
    rules: tuple[str, ...] = ()  # attack-path rules that are evidence against the control
    exposure: tuple[str, ...] = ()  # exposure finding kinds that are evidence against it
    checks: tuple[str, ...] = ()  # named process checks


@dataclass(frozen=True)
class Framework:
    id: str
    name: str
    version: str
    summary: str
    controls: tuple[Control, ...] = field(default_factory=tuple)


SURFACE = ("external_scan",)  # technical controls need a recent scan to be assessed at all
CONFIG_RULES = (
    "web_information_leak",
    "exposed_sensitive_file",
    "subdomain_takeover_candidate",
    "public_cloud_storage",
)
PATCH_RULES = ("exploitable_public_service", "end_of_life_software")
CREDENTIAL_RULES = ("credential_exposure", "leaked_secret_in_code")

FRAMEWORKS: tuple[Framework, ...] = (
    Framework("cyber_essentials", "Cyber Essentials", "v3.2 (2025)",
              "The UK government-backed baseline of five technical controls against common internet attacks.", (
        Control("CE-1", "Firewalls", "Only services that need to be reachable from the internet are exposed; "
                "administrative interfaces are not.", "direct", ("exposed_sensitive_service",), checks=SURFACE),
        Control("CE-2", "Secure configuration", "Unnecessary services, default content and forgotten systems are "
                "removed; systems do not leak information.", "direct", (*CONFIG_RULES, "tls_interception"), checks=SURFACE),
        Control("CE-3", "Security update management", "Software is supported and high or critical updates are "
                "applied within 14 days.", "direct", PATCH_RULES, checks=(*SURFACE, "patch_window", "remediation_sla")),
        Control("CE-4", "User access control", "Accounts are protected with strong authentication; credentials are "
                "not exposed.", "partial", CREDENTIAL_RULES, ("stealer_log", "breach_account"), SURFACE),
        Control("CE-5", "Malware protection", "Devices are protected against malware.", "partial",
                ("malicious_reputation",), ("stealer_log",), SURFACE),
    )),
    Framework("iso27001", "ISO/IEC 27001", "2022, Annex A",
              "The international standard for information security management systems.", (
        Control("A.5.7", "Threat intelligence", "Information about threats is collected and analysed to "
                "produce threat intelligence.", "process", checks=("threat_intel",)),
        Control("A.5.9", "Inventory of information and other associated assets", "An inventory of assets, "
                "including their owners, is kept up to date.", "partial", ("subdomain_takeover_candidate",),
                checks=SURFACE),
        Control("A.5.14", "Information transfer", "Rules protect information transferred, including by email.",
                "partial", ("spoofable_email_domain",), checks=SURFACE),
        Control("A.5.17", "Authentication information", "Passwords and other authentication information are "
                "managed and protected.", "partial", CREDENTIAL_RULES, ("stealer_log", "breach_account"), SURFACE),
        Control("A.5.19", "Information security in supplier relationships", "Risks from suppliers' products "
                "and services are identified and managed.", "process", checks=("supplier_register", "supplier_monitoring")),
        Control("A.5.22", "Monitoring of supplier services", "Supplier security practices and service delivery "
                "are monitored and reviewed regularly.", "process", checks=("supplier_monitoring",)),
        Control("A.6.3", "Information security awareness and training", "Staff receive awareness training "
                "relevant to the threats they face.", "partial",
                ("staff_enumeration", "identity_correlation", "impostor_campaign"), checks=SURFACE),
        Control("A.8.8", "Management of technical vulnerabilities", "Vulnerabilities are identified, assessed "
                "and remediated in good time.", "direct", PATCH_RULES,
                checks=(*SURFACE, "continuous_monitoring", "remediation_sla", "owned_critical")),
        Control("A.8.9", "Configuration management", "Secure configurations are defined, applied and monitored.",
                "direct", CONFIG_RULES, checks=SURFACE),
        Control("A.8.12", "Data leakage prevention", "Measures prevent sensitive information leaking.", "direct",
                ("exposed_sensitive_file", "public_cloud_storage", "leaked_secret_in_code", "web_information_leak"),
                checks=SURFACE),
        Control("A.8.16", "Monitoring activities", "Networks and systems are monitored for anomalous behaviour, "
                "and alerts are acted on.", "process", checks=("continuous_monitoring", "alerting")),
        Control("A.8.20", "Networks security", "Networks are secured and only intended services are reachable.",
                "direct", ("exposed_sensitive_service",), checks=SURFACE),
        Control("A.8.24", "Use of cryptography", "Cryptography, including transport encryption, is used "
                "effectively.", "direct", ("tls_interception",), checks=SURFACE),
    )),
    Framework("nist_csf", "NIST Cybersecurity Framework", "2.0",
              "The US NIST framework of outcomes for managing cybersecurity risk.", (
        Control("ID.AM-02", "Inventories of software, services and systems are maintained", "Know what you "
                "expose, including forgotten systems.", "partial", ("subdomain_takeover_candidate",), checks=SURFACE),
        Control("ID.RA-01", "Vulnerabilities in assets are identified and recorded", "Vulnerabilities are "
                "found, validated and recorded.", "direct", PATCH_RULES, checks=(*SURFACE, "continuous_monitoring")),
        Control("ID.RA-02", "Cyber threat intelligence is received", "Threat information from external sources "
                "is received and used.", "process", checks=("threat_intel",)),
        Control("GV.SC-07", "Supplier risks are assessed, responded to and monitored", "Risks posed by suppliers "
                "are understood and monitored over the relationship.", "process",
                checks=("supplier_register", "supplier_monitoring")),
        Control("PR.AA-01", "Identities and credentials are managed", "Credentials of users and services are "
                "managed and protected.", "partial", CREDENTIAL_RULES, ("stealer_log", "breach_account"), SURFACE),
        Control("PR.DS-01", "Data at rest is protected", "Stored data is protected against unauthorised access.",
                "direct", ("public_cloud_storage", "exposed_sensitive_file", "leaked_secret_in_code"), checks=SURFACE),
        Control("PR.DS-02", "Data in transit is protected", "Data in transit, including email, is protected.",
                "direct", ("tls_interception", "spoofable_email_domain"), checks=SURFACE),
        Control("PR.PS-02", "Software is maintained, replaced and removed", "Software is kept up to date and "
                "unsupported software is replaced.", "direct", PATCH_RULES, checks=(*SURFACE, "remediation_sla")),
        Control("PR.IR-01", "Networks are protected from unauthorised access", "Only intended network services "
                "are reachable.", "direct", ("exposed_sensitive_service",), checks=SURFACE),
        Control("DE.CM-01", "Networks and network services are monitored", "Monitoring finds potentially "
                "adverse events.", "process", checks=("continuous_monitoring", "alerting")),
    )),
    Framework("dora", "DORA", "Regulation (EU) 2022/2554",
              "The EU Digital Operational Resilience Act for financial entities.", (
        Control("Art. 8", "Identification", "ICT assets and the risks to them are identified, classified and "
                "kept up to date.", "partial", ("subdomain_takeover_candidate",),
                checks=(*SURFACE, "continuous_monitoring")),
        Control("Art. 9", "Protection and prevention", "ICT systems are protected; exposure and weaknesses are "
                "minimised.", "direct", ("exposed_sensitive_service", "tls_interception", *PATCH_RULES,
                                         *CREDENTIAL_RULES, "public_cloud_storage"), checks=SURFACE),
        Control("Art. 10", "Detection", "Anomalous activities are detected promptly, with alerting.", "process",
                checks=("continuous_monitoring", "alerting")),
        Control("Art. 13", "Learning and evolving", "Threat information and lessons are gathered and used.",
                "process", checks=("threat_intel",)),
        Control("Art. 25", "Testing of ICT tools and systems", "Vulnerability assessments and scans are carried "
                "out, and weaknesses are remediated.", "process",
                checks=(*SURFACE, "remediation_sla", "owned_critical")),
        Control("Art. 28", "ICT third-party risk", "Risks from ICT third-party providers are managed, with a "
                "register of information.", "process", checks=("supplier_register", "supplier_monitoring")),
    )),
)  # fmt: skip
BY_ID = {f.id: f for f in FRAMEWORKS}


# ---------------------------------------------------------------------------- process checks
Result = tuple[str, str, list[dict[str, str]]]  # status, reason, evidence


def _ev(label: str, detail: str) -> dict[str, str]:
    return {"label": label, "detail": detail}


def check_external_scan(ctx: dict[str, Any], now: datetime) -> Result:
    scans = ctx["own_scans"]
    if not scans:
        return "not_assessed", "None of your organisations has been scanned yet", []
    evidence = [_ev(s["target"], f"scanned {s['completed_at'][:10]} ({s['investigation_id']})") for s in scans]
    stale = [s for s in scans if now - datetime.fromisoformat(s["completed_at"]) > FRESH]
    if stale:
        return "partial", f"Evidence is older than 90 days for {', '.join(s['target'] for s in stale)}", evidence
    return "met", f"{len(scans)} organisation(s) scanned in the last 90 days", evidence


def check_continuous_monitoring(ctx: dict[str, Any], now: datetime) -> Result:
    targets = {s["target"] for s in ctx["own_scans"]}
    watched = {m["target"] for m in ctx["monitors"] if m["enabled"]}
    if not targets:
        return "not_assessed", "No organisation of yours has been scanned", []
    missing = sorted(targets - watched)
    evidence = [_ev(m["target"], f"re-scanned every {m['interval_hours']} h") for m in ctx["monitors"] if m["enabled"]]
    if not missing:
        return "met", "Every organisation is monitored continuously", evidence
    if len(missing) < len(targets):
        return "partial", f"Not monitored: {', '.join(missing)}", evidence
    return "gap", "Nothing is monitored continuously: changes go unnoticed until someone rescans", evidence


def check_alerting(ctx: dict[str, Any], now: datetime) -> Result:
    channels = [c for c in ctx["channels"] if c["enabled"]]
    if not channels:
        return "gap", "No alert destination is configured: alerts are only visible in Argus", []
    return "met", f"Alerts go to {len(channels)} destination(s)", [_ev(c["name"], c["type"]) for c in channels]


def check_remediation_sla(ctx: dict[str, Any], now: datetime) -> Result:
    m = ctx["remediation"]
    if not m or not (m["active"] or m["closed_in_window"]):
        return "not_assessed", "No remediation work is tracked yet", []
    evidence = [_ev("Fixed on time (90 days)", f"{m['sla_compliance']}%" if m["sla_compliance"] is not None else "none closed yet"),
                _ev("Overdue", str(m["overdue"])),
                _ev("Median days to fix a critical issue", str(m["mttr_days"].get("critical") or "—"))]  # fmt: skip
    if m["overdue_by_severity"]["critical"] or (m["sla_compliance"] is not None and m["sla_compliance"] < 70):
        return "gap", "Critical fixes are overdue, or most fixes miss their deadline", evidence
    if m["overdue"] or m["sla_compliance"] is None or m["sla_compliance"] < 90:
        return "partial", "Fixes are tracked, but not all within their deadline", evidence
    return "met", f"{m['sla_compliance']}% of fixes verified within deadline", evidence


def check_patch_window(ctx: dict[str, Any], now: datetime) -> Result:
    sla = ctx["policy"]["sla_days"]
    evidence = [_ev("Remediation policy", f"critical {sla['critical']} days, high {sla['high']} days")]
    if sla["critical"] <= CE_PATCH_DAYS and sla["high"] <= CE_PATCH_DAYS:
        return "met", "Your deadlines for critical and high issues are within 14 days", evidence
    return "partial", (f"Cyber Essentials expects high and critical updates within {CE_PATCH_DAYS} days; your policy "
                       f"allows {sla['high']} days for high"), evidence  # fmt: skip


def check_owned_critical(ctx: dict[str, Any], now: datetime) -> Result:
    if not ctx["own_scans"]:
        return "not_assessed", "No organisation of yours has been scanned", []
    untracked = [p for p in ctx["paths"] if p["severity"] == "critical" and not p.get("task")]
    if untracked:
        return "gap", f"{len(untracked)} critical weakness(es) have no owner or deadline", []
    return "met", "Every critical weakness has an owner and a deadline", []


def check_supplier_register(ctx: dict[str, Any], now: datetime) -> Result:
    suppliers = ctx["suppliers"]
    if not suppliers:
        return "gap", "No supplier register: third parties are not identified", []
    tiers = {t: sum(1 for s in suppliers if s["tier"] == t) for t in ("critical", "high", "medium", "low")}
    return (
        "met",
        f"{len(suppliers)} supplier(s) registered by criticality, with an exportable register",
        [_ev("Tiers", ", ".join(f"{n} {t}" for t, n in tiers.items() if n))],
    )


def check_supplier_monitoring(ctx: dict[str, Any], now: datetime) -> Result:
    suppliers = ctx["suppliers"]
    if not suppliers:
        return "not_assessed", "No suppliers registered", []
    unassessed = [s for s in suppliers if s["status"] == "not_assessed"]
    below = [s for s in suppliers if s["status"] == "below_minimum"]
    untracked = [s for s in below if not s.get("task")]
    hit = [s for s in suppliers if (s.get("exposure") or {}).get("ransomware_post")]
    evidence = [
        _ev(s["name"], f"grade {s['grade'] or '—'} (minimum {s['min_grade'] or 'none'})") for s in suppliers[:20]
    ]
    if untracked or hit:
        names = ", ".join(s["name"] for s in (untracked + hit)[:3])
        return "gap", f"Suppliers below their minimum or hit by ransomware without a response: {names}", evidence
    if below or unassessed:
        return "partial", (f"{len(below)} below minimum (with remediation in progress), "
                           f"{len(unassessed)} awaiting first assessment"), evidence  # fmt: skip
    return "met", "Every supplier is assessed continuously and meets its minimum grade", evidence


def check_threat_intel(ctx: dict[str, Any], now: datetime) -> Result:
    watches = ctx["exposure_watches"]
    monitors = [m for m in ctx["monitors"] if m["enabled"]]
    evidence = [_ev("Breach and dark-web watches", str(watches)), _ev("Continuous monitors", str(len(monitors)))]
    if watches and monitors:
        return "met", "Breach, dark-web and impersonation intelligence is collected continuously", evidence
    if watches or monitors:
        return "partial", "Some threat intelligence is collected (add exposure watching and monitoring)", evidence
    return "gap", "No external threat intelligence is collected", evidence


CHECKS: dict[str, Callable[[dict[str, Any], datetime], Result]] = {
    "external_scan": check_external_scan,
    "continuous_monitoring": check_continuous_monitoring,
    "alerting": check_alerting,
    "remediation_sla": check_remediation_sla,
    "patch_window": check_patch_window,
    "owned_critical": check_owned_critical,
    "supplier_register": check_supplier_register,
    "supplier_monitoring": check_supplier_monitoring,
    "threat_intel": check_threat_intel,
}


# ---------------------------------------------------------------------------- evaluation
def _gap_status(item: dict[str, Any]) -> str:
    serious = SEVERITY_RANK.get(item["severity"], 0) >= SEVERITY_RANK["high"]
    return "gap" if serious and not item.get("task") else "partial"


def evaluate(control: Control, ctx: dict[str, Any], now: datetime) -> dict[str, Any]:
    reasons: list[str] = []
    evidence: list[dict[str, str]] = []
    statuses: list[str] = []
    for name in control.checks:
        status, reason, ev = CHECKS[name](ctx, now)
        statuses.append(status)
        reasons.append(reason)
        evidence += ev
    surface_known = bool(ctx["own_scans"])
    gaps = []
    if control.rules and surface_known:
        gaps += [{**p, "kind": "attack_path"} for p in ctx["paths"] if p["rule"] in control.rules]
    if control.exposure:
        gaps += [{**f, "kind": "exposure", "finding_kind": f["kind"]}
                 for f in ctx["exposure_findings"] if f["kind"] in control.exposure]  # fmt: skip
    if gaps:
        statuses += [_gap_status(g) for g in gaps]
        untracked = sum(1 for g in gaps if not g.get("task"))
        reasons.insert(
            0,
            f"{len(gaps)} finding(s) against this control"
            + (f", {untracked} without an owner" if untracked else ", all being remediated"),
        )
    elif (control.rules and surface_known) or (control.exposure and ctx["exposure_watches"]):
        statuses.append("met")
        reasons.insert(0, "No findings against this control")
    assessed = [s for s in statuses if s != "not_assessed"]
    status = max(assessed, key=lambda s: STATUS_RANK[s]) if assessed else "not_assessed"
    if status == "met" and "external_scan" in control.checks and not surface_known:
        # Problems are reported without a scan, but a pass never is: a good policy is not evidence.
        status = "not_assessed"
        reasons.append("A pass needs a recent scan of your own organisation")
    gaps.sort(key=lambda g: (-SEVERITY_RANK.get(g["severity"], 0), bool(g.get("task")), g["title"]))
    return {
        "ref": control.ref, "title": control.title, "objective": control.objective, "coverage": control.coverage,
        "status": status, "reasons": [r for r in reasons if r], "evidence": evidence[:30], "gaps": gaps[:25],
        "gap_count": len(gaps),
    }  # fmt: skip


def assess_framework(framework: Framework, ctx: dict[str, Any], now: datetime) -> dict[str, Any]:
    controls = [evaluate(c, ctx, now) for c in framework.controls]
    counts = {s: sum(1 for c in controls if c["status"] == s) for s in ("met", "partial", "gap", "not_assessed")}
    assessed = len(controls) - counts["not_assessed"]
    return {
        "id": framework.id, "name": framework.name, "version": framework.version, "summary": framework.summary,
        "counts": counts, "total": len(controls),
        "assessed_pct": round(100 * assessed / len(controls)) if controls else 0,
        "met_pct": round(100 * counts["met"] / assessed) if assessed else None,
        "controls": controls,
    }  # fmt: skip


DISCLAIMER = ("Outside-in evidence from Argus. It shows where controls are visibly failing or holding from an "
              "attacker's point of view, and how security processes are run. It supports, but does not replace, "
              "an audit or certification. Control wording is paraphrased; refer to the official standards.")  # fmt: skip
