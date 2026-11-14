"""Built-in demo investigation: a fictional company with a realistic attack surface.

Lets anyone (tutors, recruiters, new users) explore every Argus feature without
scanning a real target - and without network access.

Everything is fictitious and uses *reserved* identifiers so no real person or
organisation is ever implicated:

* domains under ``.example`` (RFC 2606 - reserved for documentation),
* IP addresses from TEST-NET-3 ``203.0.113.0/24`` (RFC 5737),
* invented people, handles and breach names.

Load it with ``argus --load-demo`` (or ``POST /api/demo`` as an admin).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from argus.core.graph import IntelligenceGraph
from argus.core.models import (
    Entity,
    EntityType,
    Investigation,
    InvestigationStatus,
    Relation,
    RelationType,
    ScanConfig,
)
from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer
from argus.storage.repository import InvestigationRepository

DEMO_ID = "inv_demo_acme"
DEMO_PREVIOUS_ID = "inv_demo_acme_prev"
DEMO_TARGET = "acme-corp.example"

E, R = EntityType, RelationType

# key: (type, value, label, depth, source module, metadata)
_ENTITIES: dict[str, tuple[EntityType, str, str, int, str, dict]] = {
    "seed": (
        E.DOMAIN,
        DEMO_TARGET,
        DEMO_TARGET,
        0,
        "seed",
        {
            "dns_checked": True,
            "dmarc_policy": "missing",
            "spf": "v=spf1 include:mail.example ~all",
            "registration_date": "2009-03-14",
            "security_headers_grade": "D",
            "missing_security_headers": ["content-security-policy", "permissions-policy", "x-frame-options"],
        },
    ),
    "www": (E.SUBDOMAIN, f"www.{DEMO_TARGET}", f"www.{DEMO_TARGET}", 1, "subdomain_finder", {}),
    "vpn": (E.SUBDOMAIN, f"vpn.{DEMO_TARGET}", f"vpn.{DEMO_TARGET}", 1, "subdomain_finder", {}),
    "shop": (E.SUBDOMAIN, f"shop.{DEMO_TARGET}", f"shop.{DEMO_TARGET}", 1, "subdomain_finder", {}),
    "legacy": (
        E.SUBDOMAIN,
        f"legacy.{DEMO_TARGET}",
        f"legacy.{DEMO_TARGET}",
        1,
        "tls_analyzer",
        {"virustotal": {"malicious": 4, "suspicious": 1, "harmless": 60, "undetected": 20}},
    ),
    "heroku": (
        E.DOMAIN,
        "acme-shop-old.herokuapp.example",
        "acme-shop-old.herokuapp.example",
        2,
        "dns_recon",
        {"cname_target": True},
    ),
    "ip_web": (
        E.IP_ADDRESS,
        "203.0.113.10",
        "203.0.113.10",
        1,
        "dns_recon",
        {"country": "United Kingdom", "isp": "Example Hosting Ltd"},
    ),
    "ip_vpn": (
        E.IP_ADDRESS,
        "203.0.113.20",
        "203.0.113.20",
        2,
        "dns_recon",
        {"country": "United Kingdom", "isp": "Example Hosting Ltd"},
    ),
    "ip_db": (E.IP_ADDRESS, "203.0.113.30", "203.0.113.30", 2, "dns_recon", {}),
    "asn": (E.ASN, "AS64500", "AS64500 Example Hosting", 2, "ip_intelligence", {"as_name": "EXAMPLE-HOSTING"}),
    "p443": (
        E.PORT,
        "203.0.113.20:443",
        "Port 443 (FortiGate SSL-VPN)",
        3,
        "shodan_host",
        {"port_number": 443, "product": "FortiGate SSL-VPN", "version": "7.0.12"},
    ),
    "p3389": (E.PORT, "203.0.113.30:3389", "Port 3389 (RDP)", 3, "shodan_internetdb", {"port_number": 3389}),
    "p6379": (E.PORT, "203.0.113.30:6379", "Port 6379 (Redis)", 3, "shodan_internetdb", {"port_number": 6379}),
    # Real CVEs with their public threat intelligence (CISA KEV, FIRST EPSS, NVD CVSS) as software_intel adds it.
    "cve1": (
        E.VULNERABILITY,
        "CVE-2024-21762",
        "CVE-2024-21762",
        3,
        "shodan_host",
        {
            "cve_id": "CVE-2024-21762",
            "intel": {
                "kev": {
                    "date_added": "2024-02-09",
                    "due_date": "2024-02-16",
                    "ransomware": False,
                    "product": "Fortinet FortiOS",
                    "name": "Fortinet FortiOS Out-of-Bound Write Vulnerability",
                    "action": "Apply mitigations per vendor instructions or discontinue use of the product.",
                },
                "epss": 0.9157,
                "epss_percentile": 0.9963,
                "cvss_score": 9.8,
                "cvss_severity": "CRITICAL",
                "description": "An out-of-bounds write in FortiOS SSL-VPN may allow a remote unauthenticated "
                "attacker to execute arbitrary code or commands via specially crafted HTTP requests.",
            },
        },
    ),
    "cve2": (
        E.VULNERABILITY,
        "CVE-2023-27997",
        "CVE-2023-27997",
        3,
        "shodan_host",
        {
            "cve_id": "CVE-2023-27997",
            "intel": {
                "kev": {
                    "date_added": "2023-06-13",
                    "due_date": "2023-07-04",
                    "ransomware": False,
                    "product": "Fortinet FortiOS and FortiProxy SSL-VPN",
                    "name": "Fortinet FortiOS and FortiProxy SSL-VPN Heap-Based Buffer Overflow Vulnerability",
                    "action": "Apply updates per vendor instructions.",
                },
                "epss": 0.8706,
                "epss_percentile": 0.9941,
                "cvss_score": 9.8,
                "cvss_severity": "CRITICAL",
                "description": "A heap-based buffer overflow in FortiOS and FortiProxy SSL-VPN may allow a remote "
                "attacker to execute arbitrary code or commands via specifically crafted requests.",
            },
        },
    ),
    "nginx": (E.TECHNOLOGY, "nginx 1.18.0", "nginx 1.18.0", 2, "http_fingerprint", {"category": "Web Server"}),
    "php": (
        E.TECHNOLOGY,
        "PHP/7.4.3",
        "PHP/7.4.3",
        2,
        "http_fingerprint",
        {
            "category": "Application Framework",
            "lifecycle": {
                "product": "php",
                "version": "7.4.3",
                "cycle": "7.4",
                "eol": True,
                "eol_date": "2022-11-28",
                "latest": "7.4.33",
                "outdated": True,
            },
        },
    ),
    "cert": (
        E.CERTIFICATE,
        "TLS-Cert: 9f3c",
        "Cert: Acme Internal CA",
        2,
        "tls_analyzer",
        {
            "issuer": "Acme Internal CA",
            "self_signed": True,
            "expired": True,
            "days_remaining": -41,
            "valid_to": "2026-10-03T00:00:00+00:00",
            "observed_on": f"legacy.{DEMO_TARGET}",
        },
    ),
    "registrar": (
        E.ORGANIZATION,
        "Example Registrar Ltd",
        "Registrar: Example Registrar Ltd",
        1,
        "whois_lookup",
        {"role": "registrar"},
    ),
    "ceo": (E.PERSON, "Dana Whitfield", "Dana Whitfield", 2, "github_hunter", {"origin": "github_profile"}),
    "cfo": (E.PERSON, "Sam Okafor", "Sam Okafor", 2, "github_hunter", {"origin": "github_profile"}),
    "email_ceo": (
        E.EMAIL,
        f"dana.whitfield@{DEMO_TARGET}",
        f"dana.whitfield@{DEMO_TARGET}",
        1,
        "github_hunter",
        {"breach_count": 2},
    ),
    "email_cfo": (E.EMAIL, f"finance@{DEMO_TARGET}", f"finance@{DEMO_TARGET}", 1, "whois_lookup", {"breach_count": 0}),
    "breach1": (
        E.BREACH,
        "FitTrackr",
        "Breach: FitTrackr (2023)",
        2,
        "hibp",
        {
            "breach_date": "2023-02-11",
            "data_classes": ["Email addresses", "Passwords", "Usernames"],
            "is_verified": True,
        },
    ),
    "breach2": (
        E.BREACH,
        "PhotoShareHub",
        "Breach: PhotoShareHub (2021)",
        2,
        "hibp",
        {"breach_date": "2021-07-30", "data_classes": ["Email addresses", "IP addresses"], "is_verified": True},
    ),
    "handle": (E.USERNAME, "dwhitfield-dev", "dwhitfield-dev", 1, "seed", {}),
    "github": (
        E.SOCIAL_PROFILE,
        "https://github.example/dwhitfield-dev",
        "GitHub: dwhitfield-dev",
        2,
        "github_hunter",
        {
            "platform": "GitHub",
            "username": "dwhitfield-dev",
            "verified": True,  # proven by the Keybase account below
            "profile": {
                "display_name": "Dana Whitfield",
                "bio": "CTO at Acme. Breaking things so attackers can't.",
                "company": "Acme Corp",
                "location": "Leeds, UK",
                "created_at": "2014-09-02T10:21:00Z",
                "followers": 214,
                "public_repos": 37,
            },
        },
    ),
    "mastodon": (
        E.SOCIAL_PROFILE,
        "https://social.example/@dwhitfield-dev",
        "Mastodon: dwhitfield-dev",
        2,
        "username_hunter",
        {
            "platform": "Mastodon",
            "username": "dwhitfield-dev",
            "profile": {
                "display_name": "Dana W",
                "bio": "Security engineering, coffee and fell running.",
                "created_at": "2022-11-05T08:00:00Z",
                "followers": 389,
            },
        },
    ),
    "keybase": (
        E.SOCIAL_PROFILE,
        "https://keybase.example/dwhitfield-dev",
        "Keybase: dwhitfield-dev",
        2,
        "username_hunter",
        {
            "platform": "Keybase",
            "username": "dwhitfield-dev",
            "profile": {
                "display_name": "Dana Whitfield",
                "bio": "Keys for work and personal projects.",
                "location": "Leeds, UK",
                "created_at": "2016-05-14T19:30:00Z",
            },
        },
    ),
    "place": (E.LOCATION, "Leeds, UK", "Leeds, UK", 3, "profile_enricher", {"origin": "self-declared"}),
    "company": (E.ORGANIZATION, "Acme Corp", "Acme Corp", 3, "profile_enricher", {"origin": "self-declared employer"}),
    "website": (
        E.DOMAIN,
        "dana-whitfield.example",
        "dana-whitfield.example",
        3,
        "profile_enricher",
        {"origin": "verified link"},
    ),
}

_RELATIONS: list[tuple[str, str, RelationType, str]] = [
    ("www", "seed", R.SUBDOMAIN_OF, "Subdomain of"),
    ("vpn", "seed", R.SUBDOMAIN_OF, "Subdomain of"),
    ("shop", "seed", R.SUBDOMAIN_OF, "Subdomain of"),
    ("legacy", "seed", R.SUBDOMAIN_OF, "Subdomain of"),
    ("shop", "heroku", R.RESOLVES_TO, "CNAME Alias"),
    ("seed", "ip_web", R.RESOLVES_TO, "DNS A"),
    ("www", "ip_web", R.RESOLVES_TO, "DNS A"),
    ("vpn", "ip_vpn", R.RESOLVES_TO, "DNS A"),
    ("legacy", "ip_db", R.RESOLVES_TO, "DNS A"),
    ("ip_web", "asn", R.BELONGS_TO, "Announced by"),
    ("ip_vpn", "asn", R.BELONGS_TO, "Announced by"),
    ("ip_vpn", "p443", R.EXPOSES, "Exposes Port 443"),
    ("ip_vpn", "cve1", R.EXPOSES, "Vulnerable to"),
    ("ip_vpn", "cve2", R.EXPOSES, "Vulnerable to"),
    ("ip_db", "p3389", R.EXPOSES, "Exposes Port 3389"),
    ("ip_db", "p6379", R.EXPOSES, "Exposes Port 6379"),
    ("seed", "nginx", R.USES_TECH, "Uses"),
    ("seed", "php", R.USES_TECH, "Uses"),
    ("legacy", "cert", R.SECURED_BY, "Secured By Certificate"),
    ("registrar", "seed", R.OPERATES, "Domain Registrar"),
    ("email_ceo", "seed", R.ASSOCIATED_WITH, "Email domain"),
    ("email_cfo", "seed", R.ASSOCIATED_WITH, "Abuse/technical contact"),
    ("ceo", "email_ceo", R.HAS_ACCOUNT, "Commit email"),
    ("email_ceo", "breach1", R.EXPOSES, "Exposed in breach"),
    ("email_ceo", "breach2", R.EXPOSES, "Exposed in breach"),
    ("cfo", "email_cfo", R.ASSOCIATED_WITH, "Listed contact"),
    ("handle", "github", R.HAS_ACCOUNT, "Registered on GitHub"),
    ("handle", "mastodon", R.HAS_ACCOUNT, "Registered on Mastodon"),
    ("handle", "email_ceo", R.BELONGS_TO, "Git commit author email"),
    ("handle", "ceo", R.BELONGS_TO, "Real name"),
    ("handle", "keybase", R.HAS_ACCOUNT, "Registered on Keybase"),
    ("keybase", "github", R.ASSOCIATED_WITH, "Verified same owner"),
    ("keybase", "website", R.ASSOCIATED_WITH, "Verified website"),
    ("mastodon", "website", R.ASSOCIATED_WITH, "Verified website"),
    ("keybase", "place", R.LOCATED_IN, "Declared location"),
    ("github", "place", R.LOCATED_IN, "Declared location"),
    ("github", "company", R.ASSOCIATED_WITH, "Declared employer"),
]


# A month earlier the surface looked different - used to demonstrate drift detection.
_ABSENT_PREVIOUSLY = {"shop", "heroku", "p6379", "breach1"}
_ONLY_PREVIOUSLY: dict[str, tuple[EntityType, str, str, int, str, dict]] = {
    "p21": (E.PORT, "203.0.113.30:21", "Port 21 (FTP)", 3, "shodan_internetdb", {"port_number": 21}),
}
_PREVIOUS_METADATA: dict[str, dict] = {
    "legacy": {"virustotal": {"malicious": 0, "suspicious": 0, "harmless": 64, "undetected": 21}},
    "email_ceo": {"breach_count": 1},
}


def _build(inv_id: str, previous: bool) -> IntelligenceGraph:
    graph = IntelligenceGraph(inv_id)
    entities = dict(_ENTITIES)
    if previous:
        entities = {k: v for k, v in entities.items() if k not in _ABSENT_PREVIOUSLY} | _ONLY_PREVIOUSLY
    made: dict[str, Entity] = {}
    for key, (etype, value, label, depth, module, md) in entities.items():
        metadata = {**md, **(_PREVIOUS_METADATA.get(key, {}) if previous else {})}
        made[key] = Entity.create(etype, value, label=label, metadata=metadata, source_module=module, depth=depth)
        graph.add_entity(made[key], is_seed=depth == 0)
    relations = list(_RELATIONS) + ([("ip_db", "p21", R.EXPOSES, "Exposes Port 21")] if previous else [])
    for a, b, rtype, label in relations:
        if a in made and b in made:
            graph.add_relation(Relation.create(made[a].id, made[b].id, rtype, label=label))
    return graph


def build_demo(previous: bool = False) -> tuple[Investigation, IntelligenceGraph]:
    inv_id = DEMO_PREVIOUS_ID if previous else DEMO_ID
    graph = _build(inv_id, previous)
    finished = datetime.now(timezone.utc) - (timedelta(days=30) if previous else timedelta())
    investigation = Investigation(
        id=inv_id,
        name=f"Demo: {DEMO_TARGET} (fictional organisation{', 30 days earlier' if previous else ''})",
        config=ScanConfig(target=DEMO_TARGET, target_type=EntityType.DOMAIN, max_depth=3),
        status=InvestigationStatus.COMPLETED,
        created_at=finished - timedelta(minutes=2),
        completed_at=finished,
        node_count=graph.node_count,
        edge_count=graph.edge_count,
        analytics=GraphIntelligenceAnalyzer.analyze(graph),
        created_by="demo",
        purpose="Built-in demonstration dataset (fictional, reserved .example domains and TEST-NET IPs)",
    )
    return investigation, graph


async def load_demo(repo: InvestigationRepository) -> str:
    """Save (or refresh) the demo investigation and its earlier snapshot; returns the latest id."""
    for previous in (True, False):
        investigation, graph = build_demo(previous)
        await repo.save_investigation(investigation)
        await repo.save_graph(graph)
    return DEMO_ID
