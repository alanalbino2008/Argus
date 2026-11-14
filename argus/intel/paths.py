"""Attack Path Engine - Argus's signature capability.

Findings in isolation ("an email address", "a CVE", "no DMARC record") understate
risk. Attackers chain them: *this person's password leaked in a breach, their work
email is public on GitHub, and the company domain has no DMARC - so they can be
credential-stuffed or convincingly phished as a colleague.*

The engine reasons over the intelligence graph with a set of explainable rules.
Each rule looks for one realistic attack chain and only fires on **evidence**
(never on missing data - "DMARC unknown" is not "DMARC missing"). Every path gets:

* the chain of entities, in attack order, plus the graph edges linking them
  (so the UI can light the path up on the graph);
* the ATT&CK sequence an adversary would follow - Reconnaissance -> Resource
  Development -> Initial Access / Credential Access;
* likelihood x impact -> a 0-100 risk score and severity;
* a plain-English narrative, the evidence, and prioritised remediation.

Rules are deliberately transparent heuristics, not black-box ML: every score can be
explained in an interview or to a client.
"""

from __future__ import annotations

import hashlib
import itertools
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import asdict, dataclass, field
from typing import Any

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType
from argus.intel.attack import TECHNIQUES

# Techniques beyond Reconnaissance that paths lead to: id -> (name, tactic).
FOLLOW_ON: dict[str, tuple[str, str]] = {
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1110.004": ("Brute Force: Credential Stuffing", "Credential Access"),
    "T1566": ("Phishing", "Initial Access"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1133": ("External Remote Services", "Initial Access"),
    "T1189": ("Drive-by Compromise", "Initial Access"),
    "T1557": ("Adversary-in-the-Middle", "Credential Access"),
    "T1584": ("Compromise Infrastructure", "Resource Development"),
    "T1584.001": ("Compromise Infrastructure: Domains", "Resource Development"),
    "T1552.001": ("Unsecured Credentials: Credentials In Files", "Credential Access"),
    "T1530": ("Data from Cloud Storage", "Collection"),
    "T1110.003": ("Brute Force: Password Spraying", "Credential Access"),
    "T1213": ("Data from Information Repositories", "Collection"),
}

RISKY_PORTS: dict[int, tuple[str, int, str]] = {
    # port: (service, impact 1-5, follow-on technique)
    21: ("FTP", 3, "T1133"),
    23: ("Telnet", 4, "T1133"),
    445: ("SMB", 5, "T1133"),
    1433: ("Microsoft SQL Server", 4, "T1190"),
    2375: ("Docker API (unauthenticated)", 5, "T1190"),
    3306: ("MySQL", 4, "T1190"),
    3389: ("Remote Desktop (RDP)", 5, "T1133"),
    5432: ("PostgreSQL", 4, "T1190"),
    5900: ("VNC", 5, "T1133"),
    6379: ("Redis", 5, "T1190"),
    9200: ("Elasticsearch", 5, "T1190"),
    11211: ("Memcached", 4, "T1190"),
    27017: ("MongoDB", 5, "T1190"),
}

# Hosting providers where a dangling CNAME can be claimed by anyone (subdomain takeover).
# Matched on the provider label so regional/alternative suffixes are covered too.
TAKEOVER_MARKERS = (
    ".s3.amazonaws.",
    ".s3-website",
    ".herokuapp.",
    ".herokudns.",
    ".github.io",
    ".azurewebsites.",
    ".cloudapp.",
    ".trafficmanager.",
    ".blob.core.windows.",
    ".pantheonsite.",
    ".ghost.io",
    ".myshopify.",
    ".surge.sh",
    ".bitbucket.io",
    ".netlify.app",
    ".readthedocs.io",
    ".wpengine.",
    ".zendesk.",
)


@dataclass
class PathStep:
    entity_id: str
    label: str
    type: str
    role: str


@dataclass
class AttackPath:
    id: str
    rule: str
    anchor_id: str
    title: str
    severity: str
    score: int
    likelihood: float
    impact: int
    narrative: str
    steps: list[PathStep]
    edges: list[str]
    techniques: list[dict[str, str]]
    evidence: list[str]
    remediation: list[str]


@dataclass
class _Draft:
    rule: str
    title: str
    likelihood: float
    impact: int
    narrative: str
    steps: list[tuple[Entity, str]]
    techniques: list[str]
    evidence: list[str] = field(default_factory=list)
    remediation: list[str] = field(default_factory=list)
    # The path's subject (the email, domain, IP...). Identity = rule + anchor, so the same scenario
    # keeps its ID across scans even when its details change (e.g. a second breach appears).
    anchor: Entity | None = None


class _GraphView:
    """Undirected adjacency over the intelligence graph (attack chains ignore edge direction)."""

    def __init__(self, graph: IntelligenceGraph):
        self.entities = {e.id: e for e in graph.get_all_entities()}
        self.adj: dict[str, set[str]] = defaultdict(set)
        self.edge_ids: dict[frozenset[str], str] = {}
        for rel in graph.get_all_relations():
            if rel.source_id in self.entities and rel.target_id in self.entities:
                self.adj[rel.source_id].add(rel.target_id)
                self.adj[rel.target_id].add(rel.source_id)
                self.edge_ids.setdefault(frozenset((rel.source_id, rel.target_id)), rel.id)

    def of_type(self, *types: EntityType) -> list[Entity]:
        return sorted((e for e in self.entities.values() if e.type in types), key=lambda e: e.value)

    def neighbors(self, entity: Entity, *types: EntityType) -> list[Entity]:
        found = (self.entities[n] for n in self.adj.get(entity.id, ()))
        return sorted((e for e in found if not types or e.type in types), key=lambda e: e.value)

    def edge(self, a: Entity, b: Entity) -> str | None:
        return self.edge_ids.get(frozenset((a.id, b.id)))


def _technique(tid: str) -> dict[str, str]:
    if tid in TECHNIQUES:
        name, tactic = TECHNIQUES[tid].name, "Reconnaissance"
        parent = TECHNIQUES[tid].parent
        if parent != tid:
            name = f"{TECHNIQUES[parent].name}: {name}"
    else:
        name, tactic = FOLLOW_ON[tid]
    return {
        "id": tid,
        "name": name,
        "tactic": tactic,
        "url": "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/",
    }


def _severity(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 45:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _host_names(view: _GraphView, ip: Entity) -> list[Entity]:
    return view.neighbors(ip, EntityType.DOMAIN, EntityType.SUBDOMAIN)[:1]


# ------------------------------------------------------------------------- rules
def _credential_exposure(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    seed_domain = seed.value.lower() if seed and seed.type == EntityType.DOMAIN else None
    for email in view.of_type(EntityType.EMAIL):
        breaches = view.neighbors(email, EntityType.BREACH)
        if not breaches:
            continue
        with_passwords = [b for b in breaches if "Passwords" in b.metadata.get("data_classes", [])]
        corporate = seed_domain is not None and email.value.lower().endswith("@" + seed_domain)
        people = view.neighbors(email, EntityType.PERSON)[:1]
        top = (with_passwords or breaches)[:2]
        yield _Draft(
            rule="credential_exposure",
            anchor=email,
            title=f"Leaked credentials for {email.value}",
            likelihood=0.8 if with_passwords else 0.4,
            impact=5 if corporate else 4,
            narrative=(
                f"{email.value} appears in {len(breaches)} known breach(es)"
                + (f", {len(with_passwords)} of which exposed passwords" if with_passwords else "")
                + ". Attackers replay leaked passwords against other services (credential stuffing); "
                + (
                    "because this is a corporate address, a hit could mean access to company systems."
                    if corporate
                    else "password reuse could expose further accounts."
                )
            ),
            steps=[*((p, "identity") for p in people), (email, "account"), *((b, "breach") for b in top)],
            techniques=["T1589.001", "T1110.004", "T1078"],
            evidence=[f"Breach: {b.value} ({', '.join(b.metadata.get('data_classes', [])[:4])})" for b in top],
            remediation=[
                "Reset the password everywhere it was reused and check for suspicious sign-ins.",
                "Enforce phishing-resistant MFA on email, VPN and SSO.",
                "Adopt a password manager and block known-breached passwords at sign-up/reset.",
            ],
        )


def _spoofable_domain(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    emails = view.of_type(EntityType.EMAIL)
    for domain in view.of_type(EntityType.DOMAIN):
        policy = domain.metadata.get("dmarc_policy")
        if not domain.metadata.get("dns_checked") or policy not in ("missing", "none"):
            continue  # unknown is not missing: never alert on absent data
        staff = [e for e in emails if e.value.lower().endswith("@" + domain.value.lower())][:2]
        people = [p for e in staff for p in view.neighbors(e, EntityType.PERSON)][:1]
        yield _Draft(
            rule="spoofable_email_domain",
            anchor=domain,
            title=f"{domain.value} can be spoofed in phishing emails",
            likelihood=(0.7 if policy == "missing" else 0.5) + (0.1 if staff else 0.0),
            impact=4,
            narrative=(
                f"{domain.value} publishes {'no DMARC policy' if policy == 'missing' else 'DMARC p=none'}, "
                "so receiving mail servers are not told to reject forged mail from this domain. "
                + (
                    f"Combined with known staff addresses ({', '.join(e.value for e in staff)}), "
                    "an attacker can send convincing emails that appear to come from colleagues."
                    if staff
                    else "Anyone can send email that appears to come from it."
                )
            ),
            steps=[
                *((p, "target") for p in people),
                *((e, "impersonated sender") for e in staff),
                (domain, "spoofable domain"),
            ],
            techniques=["T1589.002", "T1566"],
            evidence=[f"DMARC policy: {policy}", f"SPF: {str(domain.metadata.get('spf', 'unknown'))[:60]}"],
            remediation=[
                "Publish DMARC with p=quarantine, monitor aggregate (rua) reports, then move to p=reject.",
                "Ensure SPF ends in -all and DKIM signing is enabled for every sending service.",
                "Train staff to verify unexpected payment or credential requests out-of-band.",
            ],
        )


def _exploitable_service(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    by_ip: dict[str, list[Entity]] = defaultdict(list)
    for vuln in view.of_type(EntityType.VULNERABILITY):
        for ip in view.neighbors(vuln, EntityType.IP_ADDRESS):
            by_ip[ip.id].append(vuln)
    for ip_id, vulns in sorted(by_ip.items()):
        ip = view.entities[ip_id]
        products = [p for p in view.neighbors(ip, EntityType.PORT) if p.metadata.get("product")][:1]
        cves = sorted({v.value for v in vulns})
        # Threat intelligence (software_intel) turns "a CVE exists" into "this CVE is being exploited".
        intel = {v.value: v.metadata.get("intel") or {} for v in vulns}
        kev = sorted(c for c, i in intel.items() if i.get("kev"))
        ransomware = sorted(c for c, i in intel.items() if (i.get("kev") or {}).get("ransomware"))
        epss = max((float(i.get("epss") or 0) for i in intel.values()), default=0.0)
        likelihood = 0.6
        if epss >= 0.1:
            likelihood = 0.75
        if kev:
            likelihood = 0.9
        if ransomware:
            likelihood = 0.95
        # Most dangerous CVEs first, so the path shows the ones that matter.
        vulns.sort(key=lambda v: (v.value not in kev, -float(intel[v.value].get("epss") or 0), v.value))
        narrative = (
            f"Public scan databases report {len(cves)} known vulnerability(ies) on {ip.value} "
            f"({', '.join(cves[:3])}{'...' if len(cves) > 3 else ''}). Attackers search the same "
            "databases to find exploitable targets, so these are likely to be probed automatically."
        )
        if kev:
            narrative += (
                f" {', '.join(kev[:3])} {'is' if len(kev) == 1 else 'are'} on CISA's Known Exploited "
                "Vulnerabilities list: attackers are actively exploiting it in the wild"
                + (", including in ransomware campaigns." if ransomware else ".")
            )
        evidence = []
        for c in cves[:5]:
            i = intel[c]
            facts = []
            if i.get("kev"):
                facts.append(f"CISA KEV since {i['kev'].get('date_added')}")
                if i["kev"].get("ransomware"):
                    facts.append("used by ransomware")
            if i.get("epss") is not None:
                facts.append(f"EPSS {float(i['epss']):.0%} chance of exploitation in 30 days")
            if i.get("cvss_score") is not None:
                facts.append(f"CVSS {i['cvss_score']} {i.get('cvss_severity') or ''}".strip())
            evidence.append(
                f"{c}: {'; '.join(facts)}" if facts else f"{c} reported by a scan database (verify the running version)"
            )
        remediation = [
            "Confirm the running versions and patch or upgrade the affected software.",
            "Remove the service from the internet or restrict it to known IP ranges/VPN.",
            "Add the host to vulnerability scanning and WAF/IPS coverage.",
        ]
        if kev:
            remediation.insert(
                0, "Treat as an emergency: patch the CISA KEV CVEs now and check the host for compromise."
            )
        yield _Draft(
            rule="exploitable_public_service",
            anchor=ip,
            title=(
                f"Actively exploited vulnerabilities exposed on {ip.value}"
                if kev
                else f"Known vulnerabilities exposed on {ip.value}"
            ),
            likelihood=likelihood,
            impact=5,
            narrative=narrative,
            steps=[
                *((h, "public hostname") for h in _host_names(view, ip)),
                (ip, "exposed host"),
                *((p, "vulnerable service") for p in products),
                *((v, "actively exploited vulnerability" if v.value in kev else "vulnerability") for v in vulns[:2]),
            ],
            techniques=["T1596.005", "T1190"],
            evidence=evidence,
            remediation=remediation,
        )


def _exposed_admin_service(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    for port in view.of_type(EntityType.PORT):
        number = port.metadata.get("port_number")
        if number not in RISKY_PORTS:
            continue
        service, impact, follow_on = RISKY_PORTS[number]
        ips = view.neighbors(port, EntityType.IP_ADDRESS)
        if not ips:
            continue
        ip = ips[0]
        yield _Draft(
            rule="exposed_sensitive_service",
            anchor=port,
            title=f"{service} exposed to the internet on {ip.value}",
            likelihood=0.5,
            impact=impact,
            narrative=(
                f"{service} (port {number}) is reachable from the internet on {ip.value}. Services like this "
                "are constantly scanned for weak or default credentials and unpatched vulnerabilities; "
                "they should almost never be publicly exposed."
            ),
            steps=[
                *((h, "public hostname") for h in _host_names(view, ip)),
                (ip, "exposed host"),
                (port, f"{service} service"),
            ],
            techniques=["T1596.005", follow_on],
            evidence=[f"Port {number}/{service} observed open"],
            remediation=[
                f"Block port {number} at the perimeter; reach {service} only via VPN or a bastion host.",
                "Require strong authentication (MFA where possible) and disable default accounts.",
            ],
        )


def _identity_correlation(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    for username in view.of_type(EntityType.USERNAME):
        profiles = view.neighbors(username, EntityType.SOCIAL_PROFILE)
        identities = view.neighbors(username, EntityType.EMAIL, EntityType.PERSON)
        if not profiles or not identities:
            continue
        yield _Draft(
            rule="identity_correlation",
            anchor=username,
            title=f"Handle '{username.value}' links to a real identity",
            likelihood=0.6,
            impact=3,
            narrative=(
                f"The handle '{username.value}' is registered on {len(profiles)} platform(s) and links to "
                f"{', '.join(i.value for i in identities[:2])}. Correlating public profiles like this lets "
                "an attacker build a detailed, believable pretext for spear-phishing."
            ),
            steps=[
                (username, "public handle"),
                *((p, "public profile") for p in profiles[:2]),
                *((i, "real identity") for i in identities[:2]),
            ],
            techniques=["T1593.001", "T1589.002", "T1566"],
            evidence=[f"Profile: {p.label}" for p in profiles[:4]],
            remediation=[
                "Use separate handles for personal and professional presence.",
                "Set Git commit email to the GitHub noreply address and scrub old history if needed.",
                "Review what each public profile reveals about role, employer and contacts.",
            ],
        )


def _tls_weakness(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    for cert in view.of_type(EntityType.CERTIFICATE):
        expired, self_signed = cert.metadata.get("expired"), cert.metadata.get("self_signed")
        if not (expired or self_signed):
            continue
        hosts = view.neighbors(cert, EntityType.DOMAIN, EntityType.SUBDOMAIN)[:1]
        problem = "an expired" if expired else "a self-signed"
        yield _Draft(
            rule="tls_interception",
            anchor=cert,
            title=f"Untrusted TLS certificate on {hosts[0].value if hosts else cert.label}",
            likelihood=0.3,
            impact=3,
            narrative=(
                f"The service presents {problem} certificate, so users see browser warnings. People trained "
                "to click through warnings cannot tell a real site from an interception attack."
            ),
            steps=[*((h, "service") for h in hosts), (cert, "untrusted certificate")],
            techniques=["T1596.003", "T1557"],
            evidence=[f"Issuer: {cert.metadata.get('issuer', '?')}, valid to {cert.metadata.get('valid_to', '?')}"],
            remediation=["Issue a publicly trusted certificate (e.g. Let's Encrypt) and automate renewal."],
        )


def _takeover_candidate(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    for target in view.of_type(EntityType.DOMAIN):
        value = target.value.lower()
        if not target.metadata.get("cname_target") or not any(m in value for m in TAKEOVER_MARKERS):
            continue
        sources = view.neighbors(target, EntityType.DOMAIN, EntityType.SUBDOMAIN)
        if not sources:
            continue
        source = sources[0]
        yield _Draft(
            rule="subdomain_takeover_candidate",
            anchor=source,
            title=f"Possible subdomain takeover: {source.value}",
            likelihood=0.3,
            impact=4,
            narrative=(
                f"{source.value} points (CNAME) to {target.value}, a third-party hosting service. If that "
                "resource has been deleted, anyone can re-register it and serve content - phishing pages, "
                f"malware or cookie theft - from {source.value}."
            ),
            steps=[(source, "subdomain"), (target, "third-party CNAME target")],
            techniques=["T1590.002", "T1584.001", "T1566"],
            evidence=[f"CNAME {source.value} -> {target.value}", "Verify whether the target resource still exists"],
            remediation=[
                "Check the third-party resource exists and is owned by you; otherwise delete the CNAME.",
                "Add DNS records to decommissioning checklists to prevent dangling records.",
            ],
        )


def _bad_reputation(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    for entity in view.of_type(EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP_ADDRESS):
        malicious = (entity.metadata.get("virustotal") or {}).get("malicious", 0)
        if malicious <= 0:
            continue
        yield _Draft(
            rule="malicious_reputation",
            anchor=entity,
            title=f"{entity.value} is flagged as malicious",
            likelihood=0.6,
            impact=4,
            narrative=(
                f"{malicious} security vendor(s) flag {entity.value} as malicious. Either the asset is "
                "already compromised and abused (hosting phishing or malware), or it is attacker "
                "infrastructure related to the target - both need investigating."
            ),
            steps=[(entity, "flagged asset")],
            techniques=["T1597.001", "T1584"],
            evidence=[f"VirusTotal: {malicious} malicious detection(s)"],
            remediation=[
                "Investigate the asset for compromise (web shells, unexpected content, outbound traffic).",
                "Once clean, request re-scanning/delisting from the flagging vendors.",
            ],
        )


def _web_information_leak(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    for site in view.of_type(EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP_ADDRESS):
        if site.metadata.get("security_headers_grade") not in ("D", "F"):
            continue
        versions = [t for t in view.neighbors(site, EntityType.TECHNOLOGY) if any(c.isdigit() for c in t.value)]
        if not versions:
            continue
        yield _Draft(
            rule="web_information_leak",
            anchor=site,
            title=f"{site.value} leaks software versions with weak browser protections",
            likelihood=0.3,
            impact=3,
            narrative=(
                f"{site.value} discloses exact software versions ({', '.join(v.value for v in versions[:2])}) and "
                f"scores {site.metadata['security_headers_grade']} on security headers, which makes "
                "matching exploits and client-side attacks easier."
            ),
            steps=[(site, "website"), *((v, "disclosed software") for v in versions[:2])],
            techniques=["T1592.002", "T1189"],
            evidence=[f"Missing headers: {', '.join(site.metadata.get('missing_security_headers', [])[:4])}"],
            remediation=[
                "Hide version banners (Server, X-Powered-By) and keep the software patched.",
                "Add Content-Security-Policy, HSTS and X-Frame-Options.",
            ],
        )


def _end_of_life_software(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    for software in view.of_type(EntityType.TECHNOLOGY, EntityType.PORT):
        life = software.metadata.get("lifecycle") or {}
        if not life.get("eol"):
            continue
        hosts = view.neighbors(software, EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP_ADDRESS)
        if not hosts:
            continue
        name = f"{life.get('product', software.value)} {life.get('version', '')}".strip()
        since = f" since {life['eol_date']}" if life.get("eol_date") else ""
        yield _Draft(
            rule="end_of_life_software",
            anchor=software,
            title=f"Unsupported software exposed: {name}",
            likelihood=0.55,
            impact=4,
            narrative=(
                f"{', '.join(h.value for h in hosts[:2])} runs {name}, whose {life.get('cycle')} release line has "
                f"been end-of-life{since}. The vendor no longer publishes security fixes, so every vulnerability "
                "found from now on stays exploitable for good."
            ),
            steps=[*((h, "public host") for h in hosts[:2]), (software, "end-of-life software")],
            techniques=["T1592.002", "T1190"],
            evidence=[
                f"{name}: release line {life.get('cycle')} end-of-life{since} (endoflife.date)",
                *([f"Latest patch release of that line: {life['latest']}"] if life.get("latest") else []),
            ],
            remediation=[
                f"Upgrade {life.get('product', 'the software')} to a supported release line.",
                "Until then, restrict access and add compensating controls (WAF, virtual patching).",
                "Hide version banners so the exact version is not advertised.",
            ],
        )


def _url_hosts(view: _GraphView, url: Entity) -> list[Entity]:
    return view.neighbors(url, EntityType.DOMAIN, EntityType.SUBDOMAIN)


def _leaked_secrets(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    for url in view.of_type(EntityType.URL):
        secrets = url.metadata.get("secrets") or []
        if url.metadata.get("category") != "code" or not secrets:
            continue
        kinds = sorted({s["type"] for s in secrets})
        repo = url.metadata.get("repository") or url.label
        yield _Draft(
            rule="leaked_secret_in_code",
            anchor=url,
            title=f"Credentials leaked in public code ({', '.join(kinds[:2])})",
            likelihood=0.85,
            impact=5,
            narrative=(
                f"The public repository {repo} mentions the organisation's domain and contains "
                f"{len(secrets)} credential(s): {', '.join(kinds)}. Bots scan public code for secrets within "
                "minutes of a push, so any of these that are still valid should be assumed compromised."
            ),
            steps=[*((h, "organisation") for h in _url_hosts(view, url)), (url, "public code")],
            techniques=["T1593.003", "T1552.001", "T1078"],
            evidence=[f"{s['type']}: {s['preview']}" for s in secrets[:5]] + [f"File: {url.value}"],
            remediation=[
                "Revoke and rotate every exposed credential now - deleting the file does not remove it from Git history.",
                "Review the provider's logs for use of the credential since the commit date.",
                "Enable secret scanning / push protection on the organisation's repositories.",
            ],
        )


def _exposed_sensitive_file(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    for url in view.of_type(EntityType.URL):
        category = url.metadata.get("category")
        live = category == "exposed_file"
        if category not in ("exposed_file", "sensitive_file", "credential_in_url"):
            continue
        what = url.metadata.get("file") or {
            "credential_in_url": "a URL carrying credentials",
            "sensitive_file": "a sensitive file",
        }.get(category, "a sensitive file")
        critical = live and any(k in url.value for k in ("/.git/", "/.env", "/actuator/env"))
        yield _Draft(
            rule="exposed_sensitive_file",
            anchor=url,
            title=(
                f"Exposed {what}: {url.label}"
                if live
                else f"Credentials in an archived URL: {url.label}"
                if category == "credential_in_url"
                else f"Sensitive file in the web archive: {url.label}"
            ),
            likelihood=0.9 if live else 0.35,
            impact=5 if critical else 4 if live else 3,
            narrative=(
                f"{url.value} serves {what} to anyone on the internet right now"
                + (" - from it an attacker can recover source code or configuration secrets." if critical else ".")
                if live
                else f"The Internet Archive holds a public copy of {url.value} ({what}), captured "
                f"{url.metadata.get('archived_on') or 'in the past'}. Even if it is gone from the site, the archived copy "
                "is public: any credentials in it must be treated as leaked."
            ),
            steps=[
                *((h, "website") for h in _url_hosts(view, url)),
                (url, "exposed file" if live else "archived copy"),
            ],
            techniques=["T1595.003" if live else "T1593", "T1552.001"],
            evidence=[
                str(url.metadata.get("evidence") or url.metadata.get("archive_url") or url.value),
                "Confirmed live by content check" if live else "Archived - not verified as currently live",
            ],
            remediation=[
                "Remove the file from the web root and block such paths at the web server/WAF.",
                "Rotate any credentials or keys the file contained.",
                *([] if live else ["Ask the Internet Archive to exclude the URL if it contains secrets."]),
            ],
        )


def _public_cloud_storage(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    for url in view.of_type(EntityType.URL):
        md = url.metadata
        if md.get("category") != "cloud_storage" or not md.get("public_listing"):
            continue
        keys = md.get("sample_keys") or []
        yield _Draft(
            rule="public_cloud_storage",
            anchor=url,
            title=f"Publicly listable cloud storage: {md.get('bucket')}",
            likelihood=0.7,
            impact=5,
            narrative=(
                f"The {md.get('provider')} bucket '{md.get('bucket')}' matches the organisation's name and anyone can "
                "list its contents. Misconfigured buckets are a leading cause of large data leaks. Ownership is "
                "inferred from the name, so confirm it - the file names below usually settle it."
            ),
            steps=[*((h, "organisation") for h in view.neighbors(url, EntityType.DOMAIN)), (url, "public bucket")],
            techniques=["T1593", "T1530"],
            evidence=[
                f"Listed objects: {', '.join(keys[:5])}" if keys else "Bucket listing is public",
                md.get("ownership", ""),
            ],
            remediation=[
                "If the bucket is yours: block public access at the account level and review what was exposed.",
                "Enable access logging and check who downloaded what.",
                "If it is not yours: no action, but watch for look-alike buckets used in phishing.",
            ],
        )


def _staff_enumeration(view: _GraphView, seed: Entity | None) -> Iterable[_Draft]:
    """Internal usernames and staff names collected from documents, GitHub and PGP enable password spraying."""
    sources = ("document_metadata", "github_org", "pgp_keyserver")
    staff = [
        e for e in view.of_type(EntityType.USERNAME, EntityType.PERSON)
        if any(s in (e.metadata.get("sources") or [e.source_module]) for s in sources)
    ]  # fmt: skip
    internal = [e for e in staff if e.type == EntityType.USERNAME and e.source_module == "document_metadata"]
    if len(staff) < 3 or seed is None:
        return
    yield _Draft(
        rule="staff_enumeration",
        anchor=seed,
        title=f"{len(staff)} staff identities harvested - enough to start password spraying",
        likelihood=0.5 if internal else 0.4,
        impact=3,
        narrative=(
            f"Public sources reveal {len(staff)} staff names and handles"
            + (
                f", including internal account names from document metadata ({', '.join(e.value for e in internal[:3])})"
                if internal
                else ""
            )
            + ". Attackers turn such lists into login names and try one common password against each account, "
            "which slips under per-account lockout."
        ),
        steps=[(seed, "organisation"), *((e, "staff identity") for e in staff[:5])],
        techniques=["T1589.003", "T1110.003", "T1078"],
        evidence=[f"{e.value} (from {e.source_module.replace('_', ' ')})" for e in staff[:6]],
        remediation=[
            "Enforce MFA on every internet-facing login (VPN, email, SSO).",
            "Detect password spraying: many accounts, few attempts each, from the same sources.",
            "Strip author metadata from documents before publishing them.",
        ],
    )


RULES: list[Callable[[_GraphView, Entity | None], Iterable[_Draft]]] = [
    _credential_exposure,
    _spoofable_domain,
    _exploitable_service,
    _exposed_admin_service,
    _identity_correlation,
    _tls_weakness,
    _takeover_candidate,
    _bad_reputation,
    _web_information_leak,
    _end_of_life_software,
    _leaked_secrets,
    _exposed_sensitive_file,
    _public_cloud_storage,
    _staff_enumeration,
]


def _finalise(view: _GraphView, draft: _Draft) -> AttackPath:
    steps: list[PathStep] = []
    seen: set[str] = set()
    for entity, role in draft.steps:
        if entity.id not in seen:
            seen.add(entity.id)
            steps.append(PathStep(entity.id, entity.label, entity.type.value, role))
    # Every graph link among the path's entities (not only consecutive ones), so the whole
    # sub-graph lights up - e.g. CVEs hang off the IP, not the port listed before them.
    edges = sorted(
        {
            edge
            for a, b in itertools.combinations(steps, 2)
            if (edge := view.edge(view.entities[a.entity_id], view.entities[b.entity_id]))
        }
    )
    likelihood = min(draft.likelihood, 1.0)
    score = round(draft.impact / 5 * likelihood * 100)
    anchor_id = draft.anchor.id if draft.anchor else "|".join(s.entity_id for s in steps)
    digest = hashlib.sha256(f"{draft.rule}|{anchor_id}".encode()).hexdigest()
    return AttackPath(
        id=f"path_{digest[:12]}",
        rule=draft.rule,
        anchor_id=anchor_id,
        title=draft.title,
        severity=_severity(score),
        score=score,
        likelihood=round(likelihood, 2),
        impact=draft.impact,
        narrative=draft.narrative,
        steps=steps,
        edges=edges,
        techniques=[_technique(t) for t in draft.techniques],
        evidence=draft.evidence,
        remediation=draft.remediation,
    )


def find_attack_paths(graph: IntelligenceGraph) -> dict[str, Any]:
    """Run every rule over the graph and return ranked attack paths with a summary."""
    view = _GraphView(graph)
    seed = next((e for e in view.entities.values() if e.depth == 0), None)
    paths = [_finalise(view, d) for rule in RULES for d in rule(view, seed)]
    paths.sort(key=lambda p: (-p.score, p.title))
    by_severity = {s: sum(p.severity == s for p in paths) for s in ("critical", "high", "medium", "low")}
    return {
        "paths": [asdict(p) for p in paths],
        "summary": {
            "total": len(paths),
            "by_severity": by_severity,
            "top_score": paths[0].score if paths else 0,
            "rules_evaluated": len(RULES),
        },
    }
