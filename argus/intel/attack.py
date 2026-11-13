"""MITRE ATT&CK mapping for reconnaissance findings (tactic TA0043 Reconnaissance).

Argus does what an adversary does *before* an attack. Mapping its findings to
ATT&CK turns "we found 40 subdomains and 3 email addresses" into the shared
language defenders use: *which reconnaissance techniques this organisation is
exposed to*, with practical guidance on reducing that exposure.

Two views are produced:

* **Exposure** - each discovered entity is classified by the kind of intelligence
  it represents (an email address is T1589.002 *Email Addresses*, a certificate is
  T1596.003 *Digital Certificates*...).
* **Emulation** - each collector declares the adversary behaviour it emulates
  (``BaseModule.attack_techniques``) and whether it is *active*, i.e. whether it
  touches the target's own infrastructure. Passive-only scans matter for bug
  bounty programmes that forbid active testing.

The result exports as an ATT&CK Navigator layer for MITRE's official viewer.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any

from argus.core.graph import IntelligenceGraph
from argus.core.models import EntityType

TACTIC_ID = "TA0043"
TACTIC_NAME = "Reconnaissance"
ATTACK_VERSION = "16"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    defence: str

    @property
    def url(self) -> str:
        return "https://attack.mitre.org/techniques/" + self.id.replace(".", "/") + "/"

    @property
    def parent(self) -> str:
        return self.id.split(".")[0]


_T = Technique
TECHNIQUES: dict[str, Technique] = {
    t.id: t
    for t in [
        _T(
            "T1589",
            "Gather Victim Identity Information",
            "Limit personal data published about staff; monitor for exposed identities.",
        ),
        _T("T1589.001", "Credentials", "Enforce MFA everywhere and monitor breach corpuses for staff credentials."),
        _T(
            "T1589.002",
            "Email Addresses",
            "Use role-based public addresses, enforce DMARC p=reject and train staff on phishing.",
        ),
        _T(
            "T1589.003",
            "Employee Names",
            "Review what staff names and roles are public; brief high-profile staff on social engineering.",
        ),
        _T(
            "T1590",
            "Gather Victim Network Information",
            "Reduce internet-facing footprint; keep an accurate asset inventory.",
        ),
        _T(
            "T1590.001",
            "Domain Properties",
            "Use registrar privacy where possible and enable registrar lock on critical domains.",
        ),
        _T(
            "T1590.002",
            "DNS",
            "Remove stale DNS records (dangling CNAMEs enable subdomain takeover); avoid revealing internal names.",
        ),
        _T(
            "T1590.004",
            "Network Topology",
            "Avoid exposing internal topology through naming, banners or public routing data.",
        ),
        _T(
            "T1590.005",
            "IP Addresses",
            "Front services with a CDN/WAF and close origin servers to direct internet access.",
        ),
        _T(
            "T1590.006",
            "Network Security Appliances",
            "Minimise banners that reveal security products and their versions.",
        ),
        _T(
            "T1591",
            "Gather Victim Org Information",
            "Review public corporate information (registrant data, org charts, supplier lists).",
        ),
        _T(
            "T1592",
            "Gather Victim Host Information",
            "Patch exposed hosts promptly; reduce information leaked in banners and headers.",
        ),
        _T(
            "T1592.002",
            "Software",
            "Hide product/version headers (Server, X-Powered-By) and keep exposed software patched.",
        ),
        _T("T1593", "Search Open Websites/Domains", "Monitor what is publicly discoverable about the organisation."),
        _T("T1593.001", "Social Media", "Provide social media guidance to staff; audit corporate accounts."),
        _T(
            "T1593.003",
            "Code Repositories",
            "Scan public repositories for secrets; set commit emails to private (GitHub noreply).",
        ),
        _T(
            "T1594",
            "Search Victim-Owned Websites",
            "Remove sensitive information (staff details, technology hints) from public websites.",
        ),
        _T("T1595", "Active Scanning", "Monitor perimeter logs for scanning; rate-limit and alert on probing."),
        _T(
            "T1596",
            "Search Open Technical Databases",
            "Assume technical databases are public; audit your footprint in them regularly.",
        ),
        _T(
            "T1596.001",
            "DNS/Passive DNS",
            "Passive DNS keeps history: retire hostnames deliberately and avoid descriptive internal names.",
        ),
        _T(
            "T1596.002", "WHOIS", "Use privacy-protected registration contacts and dedicated, monitored role mailboxes."
        ),
        _T(
            "T1596.003",
            "Digital Certificates",
            "CT logs are public: prefer wildcard certificates for internal names and keep certificates valid.",
        ),
        _T(
            "T1596.005",
            "Scan Databases",
            "Close unneeded ports and patch the CVEs that scan databases already report for your IPs.",
        ),
    ]
}

# What kind of reconnaissance intelligence each entity type represents.
ENTITY_TECHNIQUES: dict[EntityType, tuple[str, ...]] = {
    EntityType.EMAIL: ("T1589.002",),
    EntityType.PERSON: ("T1589.003",),
    EntityType.USERNAME: ("T1589",),
    EntityType.PHONE: ("T1589",),
    EntityType.SOCIAL_PROFILE: ("T1593.001",),
    EntityType.ORGANIZATION: ("T1591",),
    EntityType.DOMAIN: ("T1590.001",),
    EntityType.SUBDOMAIN: ("T1590.002",),
    EntityType.DNS_RECORD: ("T1590.002",),
    EntityType.IP_ADDRESS: ("T1590.005",),
    EntityType.ASN: ("T1590.004",),
    EntityType.CERTIFICATE: ("T1596.003",),
    EntityType.TECHNOLOGY: ("T1592.002",),
    EntityType.PORT: ("T1596.005",),
    EntityType.VULNERABILITY: ("T1596.005",),
}

MAX_EXAMPLES = 5


def map_investigation(graph: IntelligenceGraph, modules: dict[str, Any] | None = None) -> dict[str, Any]:
    """Classify an investigation's findings by ATT&CK reconnaissance technique."""
    evidence: dict[str, list[str]] = defaultdict(list)
    for entity in graph.get_all_entities():
        if entity.depth == 0:
            continue  # the seed is the target, not a finding
        for tid in ENTITY_TECHNIQUES.get(entity.type, ()):
            evidence[tid].append(entity.label)

    techniques: list[dict[str, Any]] = [
        {
            "id": tid,
            "name": TECHNIQUES[tid].name,
            "parent": TECHNIQUES[tid].parent,
            "parent_name": TECHNIQUES[TECHNIQUES[tid].parent].name,
            "url": TECHNIQUES[tid].url,
            "defence": TECHNIQUES[tid].defence,
            "count": len(labels),
            "examples": sorted(set(labels))[:MAX_EXAMPLES],
        }
        for tid, labels in evidence.items()
    ]
    techniques.sort(key=lambda t: (-t["count"], t["id"]))

    emulation = []
    for name, module in (modules or {}).items():
        ids = getattr(module, "attack_techniques", ())
        if ids:
            emulation.append(
                {"module": name, "techniques": list(ids), "active": bool(getattr(module, "active", False))}
            )

    return {
        "tactic": {"id": TACTIC_ID, "name": TACTIC_NAME, "url": f"https://attack.mitre.org/tactics/{TACTIC_ID}/"},
        "techniques": techniques,
        "technique_count": len(techniques),
        "emulation": emulation,
    }


def to_navigator_layer(mapping: dict[str, Any], name: str, description: str = "") -> dict[str, Any]:
    """ATT&CK Navigator layer (format 4.5); open at https://mitre-attack.github.io/attack-navigator/."""
    scores: dict[str, int] = defaultdict(int)
    comments: dict[str, str] = {}
    for tech in mapping["techniques"]:
        scores[tech["id"]] += tech["count"]
        comments[tech["id"]] = f"{tech['count']} finding(s), e.g. {', '.join(tech['examples'][:3])}"
        if tech["parent"] != tech["id"]:
            scores[tech["parent"]] += tech["count"]  # roll sub-techniques up for the matrix view
    top = max(scores.values(), default=1)
    return {
        "name": name[:100],
        "versions": {"attack": ATTACK_VERSION, "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description or "Reconnaissance exposure discovered by Argus OSINT",
        "filters": {"platforms": ["PRE"]},
        "sorting": 3,
        "layout": {"layout": "side", "showName": True, "showID": True, "aggregateFunction": "max"},
        "hideDisabled": False,
        "techniques": [
            {
                "techniqueID": tid,
                "tactic": "reconnaissance",
                "score": score,
                "comment": comments.get(tid, "Rolled up from sub-techniques"),
                "enabled": True,
                "showSubtechniques": True,
            }
            for tid, score in sorted(scores.items())
        ],
        "gradient": {"colors": ["#fff3b0", "#ff9f43", "#ee5253"], "minValue": 0, "maxValue": top},
        "legendItems": [],
        "metadata": [{"name": "generator", "value": "Argus OSINT"}],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#205b8f",
        "selectTechniquesAcrossTactics": False,
    }
