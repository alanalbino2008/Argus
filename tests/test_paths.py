"""Attack Path Engine: each rule fires on evidence, stays silent on missing data, and ranks sensibly."""

from argus.core.graph import IntelligenceGraph
from argus.core.models import Entity, EntityType, Relation, RelationType
from argus.intel.paths import find_attack_paths

E = EntityType


def build(*, seed="acme.com", entities=(), links=()):
    g = IntelligenceGraph("t")
    s = Entity.create(E.DOMAIN, seed, depth=0)
    g.add_entity(s, is_seed=True)
    made = {"seed": s}
    for key, etype, value, md in entities:
        made[key] = Entity.create(etype, value, depth=1, metadata=md)
        if made[key].id == s.id:  # same domain as the seed: merge facts into it
            s.metadata.update(md)
            made[key] = s
        else:
            g.add_entity(made[key])
    for a, b in links:
        g.add_relation(Relation.create(made[a].id, made[b].id, RelationType.ASSOCIATED_WITH))
    return g, made


def rules(graph):
    return [p["rule"] for p in find_attack_paths(graph)["paths"]]


def only(graph, rule):
    return next(p for p in find_attack_paths(graph)["paths"] if p["rule"] == rule)


# ------------------------------------------------------------- credential exposure
def test_corporate_password_breach_is_critical_with_full_chain():
    g, _ = build(
        entities=[
            ("person", E.PERSON, "Jane Doe", {}),
            ("email", E.EMAIL, "jane@acme.com", {}),
            ("breach", E.BREACH, "Adobe", {"data_classes": ["Email addresses", "Passwords"]}),
        ],
        links=[("person", "email"), ("email", "breach")],
    )
    path = only(g, "credential_exposure")
    assert path["severity"] == "critical" and path["score"] == 80
    assert [s["role"] for s in path["steps"]] == ["identity", "account", "breach"]
    assert len(path["edges"]) == 2  # every consecutive step is linked on the graph
    assert [t["id"] for t in path["techniques"]] == ["T1589.001", "T1110.004", "T1078"]
    assert path["techniques"][-1]["tactic"] == "Initial Access"


def test_breach_without_passwords_scores_lower():
    g, _ = build(
        entities=[
            ("email", E.EMAIL, "jane@other.org", {}),
            ("breach", E.BREACH, "Canva", {"data_classes": ["Email addresses"]}),
        ],
        links=[("email", "breach")],
    )
    assert only(g, "credential_exposure")["score"] < 45


# ------------------------------------------------------------------ email spoofing
def test_missing_dmarc_with_known_staff_is_a_phishing_path():
    g, _ = build(
        entities=[
            ("seed", E.DOMAIN, "acme.com", {"dns_checked": True, "dmarc_policy": "missing", "spf": "missing"}),
            ("email", E.EMAIL, "ceo@acme.com", {}),
        ],
        links=[("email", "seed")],
    )
    path = only(g, "spoofable_email_domain")
    # High, not critical: spoofing still needs a crafted lure; critical is reserved for chains that
    # hand an attacker access more directly (e.g. leaked passwords for a corporate account).
    assert path["severity"] == "high" and path["score"] == 64
    assert "ceo@acme.com" in path["narrative"]
    assert path["techniques"][-1]["id"] == "T1566"


def test_unknown_dmarc_never_alerts():
    g, _ = build(entities=[("seed", E.DOMAIN, "acme.com", {"dns_checked": True, "dmarc_policy": "unknown"})])
    assert "spoofable_email_domain" not in rules(g)
    g, _ = build()  # DNS never checked at all
    assert "spoofable_email_domain" not in rules(g)


def test_enforced_dmarc_never_alerts():
    g, _ = build(entities=[("seed", E.DOMAIN, "acme.com", {"dns_checked": True, "dmarc_policy": "reject"})])
    assert rules(g) == []


# ------------------------------------------------------------ infrastructure paths
def test_vulnerable_service_chain_from_hostname_to_cve():
    g, _ = build(
        entities=[
            ("sub", E.SUBDOMAIN, "vpn.acme.com", {}),
            ("ip", E.IP_ADDRESS, "203.0.113.10", {}),
            ("port", E.PORT, "203.0.113.10:443", {"port_number": 443, "product": "FortiGate"}),
            ("cve", E.VULNERABILITY, "CVE-2024-21762", {}),
        ],
        links=[("sub", "ip"), ("ip", "port"), ("ip", "cve")],
    )
    path = only(g, "exploitable_public_service")
    assert [s["type"] for s in path["steps"]] == ["subdomain", "ip_address", "port", "vulnerability"]
    assert path["techniques"][-1]["id"] == "T1190" and path["severity"] == "high"


def test_exposed_rdp_is_flagged_but_https_is_not():
    g, _ = build(
        entities=[
            ("ip", E.IP_ADDRESS, "203.0.113.20", {}),
            ("rdp", E.PORT, "203.0.113.20:3389", {"port_number": 3389}),
            ("web", E.PORT, "203.0.113.20:443", {"port_number": 443}),
        ],
        links=[("ip", "rdp"), ("ip", "web")],
    )
    paths = [p for p in find_attack_paths(g)["paths"] if p["rule"] == "exposed_sensitive_service"]
    assert len(paths) == 1 and "Remote Desktop" in paths[0]["title"]
    assert paths[0]["techniques"][-1]["id"] == "T1133"


def test_subdomain_takeover_candidate():
    g, _ = build(
        entities=[
            ("sub", E.SUBDOMAIN, "shop.acme.com", {}),
            ("cname", E.DOMAIN, "acme-shop.herokuapp.com", {"cname_target": True}),
        ],
        links=[("sub", "cname")],
    )
    path = only(g, "subdomain_takeover_candidate")
    assert path["techniques"][1]["tactic"] == "Resource Development"
    # an ordinary CNAME to a non-takeover-prone service is not flagged
    g, _ = build(
        entities=[
            ("sub", E.SUBDOMAIN, "www.acme.com", {}),
            ("cname", E.DOMAIN, "acme.edgekey.net", {"cname_target": True}),
        ],
        links=[("sub", "cname")],
    )
    assert "subdomain_takeover_candidate" not in rules(g)


# ------------------------------------------------------------------ identity & misc
def test_identity_correlation_needs_a_real_identity():
    g, _ = build(
        entities=[
            ("user", E.USERNAME, "jdoe", {}),
            ("gh", E.SOCIAL_PROFILE, "https://github.com/jdoe", {}),
        ],
        links=[("user", "gh")],
    )
    assert "identity_correlation" not in rules(g)  # handle alone is not enough
    g, _ = build(
        entities=[
            ("user", E.USERNAME, "jdoe", {}),
            ("gh", E.SOCIAL_PROFILE, "https://github.com/jdoe", {}),
            ("email", E.EMAIL, "john@personal.example", {}),
        ],
        links=[("user", "gh"), ("user", "email")],
    )
    assert "identity_correlation" in rules(g)


def test_tls_reputation_and_web_rules():
    g, _ = build(
        entities=[
            (
                "sub",
                E.SUBDOMAIN,
                "old.acme.com",
                {
                    "virustotal": {"malicious": 3},
                    "security_headers_grade": "F",
                    "missing_security_headers": ["content-security-policy"],
                },
            ),
            ("cert", E.CERTIFICATE, "TLS-Cert: ff", {"expired": True, "issuer": "R3"}),
            ("tech", E.TECHNOLOGY, "Apache 2.4.49", {}),
        ],
        links=[("sub", "cert"), ("sub", "tech")],
    )
    assert {"tls_interception", "malicious_reputation", "web_information_leak"} <= set(rules(g))


def test_paths_are_ranked_deduplicated_and_summarised():
    g, _ = build(
        entities=[
            ("seed", E.DOMAIN, "acme.com", {"dns_checked": True, "dmarc_policy": "none"}),
            ("ip", E.IP_ADDRESS, "203.0.113.30", {}),
            ("ftp", E.PORT, "203.0.113.30:21", {"port_number": 21}),
        ],
        links=[("seed", "ip"), ("ip", "ftp")],
    )
    result = find_attack_paths(g)
    scores = [p["score"] for p in result["paths"]]
    assert scores == sorted(scores, reverse=True)
    assert len({p["id"] for p in result["paths"]}) == len(result["paths"])
    assert result["summary"]["total"] == 2 and result["summary"]["rules_evaluated"] == 10
    assert find_attack_paths(g)["paths"] == result["paths"]  # deterministic


def test_empty_graph_has_no_paths():
    g, _ = build()
    assert find_attack_paths(g)["summary"]["total"] == 0


# ------------------------------------------------------------- threat intelligence
def test_kev_and_ransomware_cves_raise_likelihood_and_lead_the_path():
    kev = {"kev": {"date_added": "2024-02-09", "ransomware": True}, "epss": 0.94, "cvss_score": 9.8}
    g, _ = build(
        entities=[
            ("ip", E.IP_ADDRESS, "203.0.113.40", {}),
            ("old", E.VULNERABILITY, "CVE-2019-0001", {"intel": {"kev": None, "epss": 0.01}}),
            ("hot", E.VULNERABILITY, "CVE-2024-21762", {"intel": kev}),
        ],
        links=[("old", "ip"), ("hot", "ip")],
    )
    path = only(g, "exploitable_public_service")
    assert path["likelihood"] == 0.95 and path["severity"] == "critical"
    assert path["title"].startswith("Actively exploited")
    assert "ransomware" in path["narrative"]
    roles = {s["label"]: s["role"] for s in path["steps"]}
    assert roles["CVE-2024-21762"] == "actively exploited vulnerability"
    assert path["steps"][1]["label"] == "CVE-2024-21762"  # most dangerous first
    assert any("CISA KEV since 2024-02-09" in e and "EPSS 94%" in e for e in path["evidence"])
    assert path["remediation"][0].startswith("Treat as an emergency")


def test_plain_cves_keep_baseline_likelihood():
    g, _ = build(
        entities=[("ip", E.IP_ADDRESS, "203.0.113.41", {}), ("v", E.VULNERABILITY, "CVE-2019-0001", {})],
        links=[("v", "ip")],
    )
    path = only(g, "exploitable_public_service")
    assert path["likelihood"] == 0.6 and path["title"].startswith("Known")


def test_end_of_life_software_needs_an_exposed_host():
    life = {
        "product": "php",
        "version": "7.4.3",
        "cycle": "7.4",
        "eol": True,
        "eol_date": "2022-11-28",
        "latest": "7.4.33",
    }
    g, _ = build(
        entities=[("sub", E.SUBDOMAIN, "shop.acme.com", {}), ("php", E.TECHNOLOGY, "PHP/7.4.3", {"lifecycle": life})],
        links=[("sub", "php")],
    )
    path = only(g, "end_of_life_software")
    assert path["title"] == "Unsupported software exposed: php 7.4.3"
    assert "since 2022-11-28" in path["narrative"]
    assert [t["id"] for t in path["techniques"]] == ["T1592.002", "T1190"]

    lonely, _ = build(entities=[("php", E.TECHNOLOGY, "PHP/7.4.3", {"lifecycle": life})])
    assert "end_of_life_software" not in rules(lonely)
    supported, _ = build(
        entities=[
            ("sub", E.SUBDOMAIN, "a.acme.com", {}),
            ("p", E.TECHNOLOGY, "PHP/8.3.1", {"lifecycle": {"eol": False}}),
        ],
        links=[("sub", "p")],
    )
    assert "end_of_life_software" not in rules(supported)
