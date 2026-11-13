"""Collector parsing tests against recorded-style API responses (no network).

Each module talks to a third-party API. These tests replay realistic responses
through a fake HTTP session and real dnspython record objects, so we verify what
every module *extracts* - the TLS bug showed a module can "succeed" while
silently extracting nothing.
"""

from __future__ import annotations

import json
import re
from typing import Any

import dns.asyncresolver
import dns.rdata
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import pytest
from multidict import CIMultiDict

from argus.core.models import Entity, EntityType, RelationType, ScanConfig
from argus.modules.identity import username_hunter
from argus.modules.identity.email_recon import EmailReconModule
from argus.modules.identity.github_hunter import GitHubHunterModule
from argus.modules.identity.phone_recon import PhoneReconModule
from argus.modules.identity.username_hunter import UsernameHunterModule
from argus.modules.infrastructure.dns_recon import DnsReconModule
from argus.modules.infrastructure.http_fingerprint import HttpFingerprintModule
from argus.modules.infrastructure.ip_intelligence import IpIntelligenceModule
from argus.modules.infrastructure.shodan_internetdb import ShodanInternetDbModule
from argus.modules.infrastructure.subdomain_finder import SubdomainFinderModule
from argus.modules.infrastructure.whois_lookup import WhoisLookupModule

CONFIG = ScanConfig(target="x", target_type=EntityType.DOMAIN)


# ----------------------------------------------------------------------------- fakes
class FakeResponse:
    def __init__(self, status: int = 200, body: Any = "", headers: dict[str, str] | None = None):
        self.status = status
        self._body = body if isinstance(body, str) else json.dumps(body)
        self.headers = CIMultiDict(headers or {})

    async def json(self, content_type: str | None = None) -> Any:
        return json.loads(self._body)

    async def text(self, errors: str = "strict") -> str:
        return self._body

    def release(self) -> None:
        pass


class FakeSession:
    """Routes URLs (regex) to canned responses; anything else is a 404."""

    def __init__(self, routes: dict[str, FakeResponse]):
        self.routes = routes
        self.requested: list[str] = []

    def get(self, url: str, **_: Any) -> _Ctx:
        self.requested.append(url)
        for pattern, response in self.routes.items():
            if re.search(pattern, url):
                return _Ctx(response)
        return _Ctx(FakeResponse(404, "not found"))


class _Ctx:
    def __init__(self, response: FakeResponse):
        self.response = response

    async def __aenter__(self) -> FakeResponse:
        return self.response

    async def __aexit__(self, *exc: Any) -> None:
        return None


def rr(rtype: str, *texts: str) -> list[Any]:
    """Real dnspython rdata objects built from zone-file text."""
    return [dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.from_text(rtype), t) for t in texts]


@pytest.fixture
def fake_dns(monkeypatch):
    """Answer DNS queries from a {(name, type): [rdata]} table; unknown names are NXDOMAIN."""
    table: dict[tuple[str, str], list[Any]] = {}

    async def resolve(self, qname, rdtype="A", *args, **kwargs):
        key = (str(qname).rstrip(".").lower(), str(rdtype))
        if key not in table:
            raise dns.resolver.NXDOMAIN
        return table[key]

    monkeypatch.setattr(dns.asyncresolver.Resolver, "resolve", resolve)
    return table


async def collect(module, entity, session=None):
    items = [x async for x in module.run(entity, session or FakeSession({}), CONFIG)]
    entities = [x for x in items if isinstance(x, Entity)]
    relations = [x for x in items if not isinstance(x, Entity)]
    return entities, relations


def values(entities, etype):
    return sorted(e.value for e in entities if e.type == etype)


# ----------------------------------------------------------------------------- DNS
async def test_dns_recon_extracts_records_and_email_security(fake_dns):
    fake_dns.update(
        {
            ("example.com", "A"): rr("A", "93.184.216.34"),
            ("example.com", "MX"): rr("MX", "10 mail.example.com."),
            ("example.com", "NS"): rr("NS", "ns1.example.net."),
            ("example.com", "TXT"): rr("TXT", '"v=spf1 include:_spf.example.net -all"'),
            ("_dmarc.example.com", "TXT"): rr("TXT", '"v=DMARC1; p=reject"'),
        }
    )
    entities, relations = await collect(DnsReconModule(), Entity.create(EntityType.DOMAIN, "example.com"))
    assert values(entities, EntityType.IP_ADDRESS) == ["93.184.216.34"]
    assert "mail.example.com" in values(entities, EntityType.DOMAIN)
    labels = {e.label for e in entities if e.type == EntityType.DNS_RECORD}
    assert {"SPF Policy", "DMARC Policy"} <= labels
    assert any(r.type == RelationType.RESOLVES_TO for r in relations)


async def test_email_recon_mx_disposable_and_username(fake_dns):
    fake_dns[("example.com", "MX")] = rr("MX", "5 mx.example.com.")
    entities, _ = await collect(EmailReconModule(), Entity.create(EntityType.EMAIL, "Jane.Doe@Example.com"))
    assert values(entities, EntityType.USERNAME) == ["jane.doe"]
    domain = next(e for e in entities if e.type == EntityType.DOMAIN)
    assert domain.metadata["has_valid_mx"] is True
    assert domain.metadata["mx_records"] == ["mx.example.com"]

    entities, _ = await collect(EmailReconModule(), Entity.create(EntityType.EMAIL, "x@mailinator.com"))
    domain = next(e for e in entities if e.type == EntityType.DOMAIN)
    assert domain.metadata["is_disposable_provider"] is True
    assert domain.metadata["has_valid_mx"] is False  # NXDOMAIN in the fake = authoritative "no"


async def test_ip_intelligence_ptr_and_geo(fake_dns):
    fake_dns[("34.216.184.93.in-addr.arpa", "PTR")] = rr("PTR", "edge.example.net.")
    session = FakeSession(
        {
            r"ip-api\.com/json/93\.184\.216\.34": FakeResponse(
                body={
                    "status": "success",
                    "country": "United States",
                    "countryCode": "US",
                    "city": "Norwell",
                    "isp": "Edgecast",
                    "org": "Example Org",
                    "as": "AS15133 Edgecast Inc.",
                    "asname": "EDGECAST",
                }
            )
        }
    )
    ip = Entity.create(EntityType.IP_ADDRESS, "93.184.216.34")
    entities, _ = await collect(IpIntelligenceModule(), ip, session)
    assert values(entities, EntityType.DOMAIN) == ["edge.example.net"]
    assert values(entities, EntityType.ASN) == ["AS15133"]
    assert ip.metadata["countryCode"] == "US"


# ----------------------------------------------------------------------------- HTTP APIs
async def test_whois_rdap_registrar_and_abuse_contact():
    rdap = {
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"},
        ],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"], ["fn", {}, "text", "RESERVED-IANA"]]],
            },
            {
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Abuse Desk"], ["email", {}, "text", "abuse@iana.org"]]],
            },
        ],
    }
    domain = Entity.create(EntityType.DOMAIN, "example.com")
    entities, _ = await collect(
        WhoisLookupModule(), domain, FakeSession({r"rdap\.org/domain/example\.com": FakeResponse(body=rdap)})
    )
    assert values(entities, EntityType.ORGANIZATION) == ["RESERVED-IANA"]
    assert values(entities, EntityType.EMAIL) == ["abuse@iana.org"]
    assert domain.metadata["registration_date"] == "1995-08-14T04:00:00Z"


async def test_subdomain_finder_merges_ct_and_passive_dns():
    session = FakeSession(
        {
            r"crt\.sh": FakeResponse(
                body=[
                    {"name_value": "www.example.com\n*.api.example.com"},
                    {"name_value": "example.com"},  # apex: ignored
                    {"name_value": "evil.com"},  # out of scope: ignored
                ]
            ),
            r"hackertarget": FakeResponse(body="mail.example.com,93.184.216.34\nwww.example.com,93.184.216.34"),
        }
    )
    entities, relations = await collect(
        SubdomainFinderModule(), Entity.create(EntityType.DOMAIN, "example.com"), session
    )
    assert values(entities, EntityType.SUBDOMAIN) == ["api.example.com", "mail.example.com", "www.example.com"]
    assert all(r.type == RelationType.SUBDOMAIN_OF for r in relations)


async def test_shodan_internetdb_ports_cves_hostnames():
    session = FakeSession(
        {
            r"internetdb\.shodan\.io/8\.8\.8\.8": FakeResponse(
                body={
                    "ports": [53, 443],
                    "cves": ["CVE-2023-0001"],
                    "hostnames": ["dns.google"],
                    "tags": [],
                }
            )
        }
    )
    entities, _ = await collect(ShodanInternetDbModule(), Entity.create(EntityType.IP_ADDRESS, "8.8.8.8"), session)
    assert values(entities, EntityType.PORT) == ["8.8.8.8:443", "8.8.8.8:53"]
    assert values(entities, EntityType.VULNERABILITY) == ["CVE-2023-0001"]
    assert values(entities, EntityType.DOMAIN) == ["dns.google"]


async def test_shodan_never_sends_private_ips_to_third_party():
    session = FakeSession({})
    entities, _ = await collect(ShodanInternetDbModule(), Entity.create(EntityType.IP_ADDRESS, "10.0.0.5"), session)
    assert entities == [] and session.requested == []


async def test_github_profile_and_commit_email_unmasking():
    session = FakeSession(
        {
            r"api\.github\.com/users/octo$": FakeResponse(
                body={
                    "name": "Octo Cat",
                    "company": "@acme",
                    "blog": "https://octo.example.org/blog/",
                    "twitter_username": "octocat",
                }
            ),
            r"api\.github\.com/users/octo/events/public": FakeResponse(
                body=[
                    {
                        "type": "PushEvent",
                        "payload": {
                            "commits": [
                                {"author": {"email": "octo@personal.example"}},
                                {"author": {"email": "1234+octo@users.noreply.github.com"}},  # anonymised: ignored
                            ]
                        },
                    },
                    {"type": "WatchEvent", "payload": {}},
                ]
            ),
        }
    )
    entities, _ = await collect(GitHubHunterModule(), Entity.create(EntityType.USERNAME, "octo"), session)
    assert values(entities, EntityType.PERSON) == ["Octo Cat"]
    assert values(entities, EntityType.ORGANIZATION) == ["acme"]
    assert values(entities, EntityType.DOMAIN) == ["octo.example.org"]  # bare hostname, no path
    assert values(entities, EntityType.EMAIL) == ["octo@personal.example"]


async def test_http_fingerprint_tech_stack_and_grade():
    session = FakeSession(
        {
            r"https://example\.com": FakeResponse(
                headers={
                    "Server": "cloudflare",
                    "CF-RAY": "8a1b",
                    "X-Powered-By": "Express",
                    "Strict-Transport-Security": "max-age=63072000",
                }
            )
        }
    )
    site = Entity.create(EntityType.DOMAIN, "example.com")
    entities, _ = await collect(HttpFingerprintModule(), site, session)
    tech = values(entities, EntityType.TECHNOLOGY)
    assert {"Cloudflare CDN & WAF", "Express", "cloudflare"} <= set(tech)
    assert site.metadata["security_headers_grade"] == "F"  # 1 of the checked headers present
    assert "content-security-policy" in site.metadata["missing_security_headers"]


async def test_username_hunter_detection_strategies(monkeypatch):
    monkeypatch.setattr(
        username_hunter,
        "PLATFORM_SIGNATURES",
        [
            {
                "name": "CodeHub",
                "url_template": "https://codehub.test/{}",
                "check_url": "https://codehub.test/{}",
                "check_type": "status_code",
            },
            {
                "name": "Forum",
                "url_template": "https://forum.test/u/{}",
                "check_url": "https://forum.test/u/{}",
                "check_type": "body_not_contains",
                "missing_text": "User not found",
            },
            {
                "name": "Ghost",
                "url_template": "https://ghost.test/{}",
                "check_url": "https://ghost.test/{}",
                "check_type": "status_code",
            },
        ],
    )
    session = FakeSession(
        {
            r"codehub\.test/jdoe": FakeResponse(200, "<h1>jdoe</h1>"),
            r"forum\.test/u/jdoe": FakeResponse(200, "<p>User not found</p>"),  # soft-404: not a hit
        }
    )
    entities, _ = await collect(UsernameHunterModule(), Entity.create(EntityType.USERNAME, "jdoe"), session)
    assert values(entities, EntityType.SOCIAL_PROFILE) == ["https://codehub.test/jdoe"]


# ----------------------------------------------------------------------------- offline
async def test_phone_recon_country_attribution():
    phone = Entity.create(EntityType.PHONE, "+44 20 7946 0958")
    await collect(PhoneReconModule(), phone)
    assert phone.metadata["country_code"] == "GB"
