"""Infrastructure pivoting: from one domain to the rest of its operator's infrastructure.

**For the scan's own domain**, related domains are found through what they share
(``argus/intel/pivots.py`` explains the evidence and its weights):

* analytics / ad / tag IDs, read from the homepage **as archived by the Internet Archive**
  (the target is not contacted), then looked up in reverse;
* the organisation named in the domain's OV/EV certificates (crt.sh), then every certificate
  issued to that organisation;
* dedicated (non-generic) name servers, and IP addresses shared with few other domains.

Discovered domains are recorded with their evidence and a confidence, and marked
``out_of_scope``. Finding a probable sibling is not permission to scan it; the analyst decides
and starts a separately authorised investigation.

**For impostor domains** found by ``lookalike_domains``, the module maps the attacker's
infrastructure: other domains on the impostor's server that also imitate the brand. It is
*third-party-safe*: it never contacts the impostor, it only asks public databases about it.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import quote

import aiohttp
import dns.asyncresolver
import dns.exception
import dns.resolver
from cryptography import x509
from cryptography.x509.oid import NameOID

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.core.settings import get_settings
from argus.intel.lookalikes import registrable, split_domain
from argus.intel.pivots import (
    MAX_COHOSTED,
    MAX_SHARED_NS,
    Evidence,
    combine,
    domains_in,
    extract_trackers,
    is_generic_ns,
    is_generic_org,
    looks_like_brand,
)
from argus.modules.base import BaseModule
from argus.modules.threat_intel.lookalike_domains import risk_score

logger = logging.getLogger("argus.module.infrastructure_pivot")

HT = "https://api.hackertarget.com"
MAX_RELATED = 40
MAX_IMPOSTOR_SIBLINGS = 15
HT_ERRORS = ("error", "api count exceeded", "no records", "no dns a records", "invalid")


def _registrable(host: str) -> str | None:
    try:
        return registrable(host)
    except ValueError:
        return None


class InfrastructurePivotModule(BaseModule):
    name = "infrastructure_pivot"
    description = (
        "Related domains via shared analytics IDs, certificate organisation, name servers and IPs; impostor clusters"
    )
    supported_entity_types = [EntityType.DOMAIN]
    attack_techniques = ("T1596.001", "T1596.003", "T1593")
    third_party_safe = True
    rate_limits = {"api.hackertarget.com": 2.0, "crt.sh": 1.0, "archive.org": 1.0, "web.archive.org": 1.0}

    def can_handle(self, entity: Entity) -> bool:
        if not super().can_handle(entity):
            return False
        if entity.metadata.get("out_of_scope"):  # only suspicious impostors, never other third parties
            return (entity.metadata.get("lookalike") or {}).get("verdict") == "suspicious"
        return entity.depth == 0

    # ------------------------------------------------------------------ sources
    def _ht(self, path: str, query: str) -> str:
        key = get_settings().hackertarget_api_key
        suffix = f"&apikey={quote(key.get_secret_value())}" if key else ""
        return f"{HT}/{path}/?q={quote(query)}{suffix}"

    async def _text(self, session: HttpClient, url: str) -> str | None:
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=20)) as resp:
                if resp.status != 200:
                    self.report_error(url.split("/")[2], f"HTTP {resp.status}")
                    return None
                text = await resp.text()
        except Exception as exc:
            self.report_error(url.split("/")[2], exc)
            return None
        if text.strip().lower().startswith(HT_ERRORS):
            return None
        return text

    async def _reverse_ip(self, session: HttpClient, ip: str) -> list[str]:
        text = await self._text(session, self._ht("reverseiplookup", ip))
        return domains_in(text) if text else []

    async def _shared_ns(self, session: HttpClient, ns: str) -> list[str]:
        text = await self._text(session, self._ht("findshareddns", ns))
        return domains_in(text) if text else []

    async def _analytics(self, session: HttpClient, tracker: str) -> list[str]:
        text = await self._text(session, self._ht("analyticslookup", tracker))
        return domains_in(text) if text else []

    async def _archived_homepage(self, session: HttpClient, domain: str) -> str | None:
        """The latest Internet Archive snapshot of the homepage (raw, without the archive's toolbar)."""
        try:
            async with session.get(f"https://archive.org/wayback/available?url={quote(domain)}") as resp:
                data = await resp.json(content_type=None) if resp.status == 200 else {}
        except Exception as exc:
            self.report_error("archive.org", exc)
            return None
        closest = ((data or {}).get("archived_snapshots") or {}).get("closest") or {}
        timestamp, original = closest.get("timestamp"), closest.get("url")
        if not (closest.get("available") and timestamp and original):
            return None
        return await self._text(session, f"https://web.archive.org/web/{timestamp}id_/{original}")

    async def _certificate_org(self, session: HttpClient, domain: str) -> str | None:
        """The verified organisation (O=) on the domain's most recent OV/EV certificate."""
        try:
            async with session.get(f"https://crt.sh/?q={quote(domain)}&output=json") as resp:
                rows = await resp.json(content_type=None) if resp.status == 200 else []
        except Exception as exc:
            self.report_error("crt.sh", exc)
            return None
        rows = sorted((r for r in rows or [] if isinstance(r, dict)), key=lambda r: str(r.get("not_before", "")),
                      reverse=True)  # fmt: skip
        # Domain-validated certificates carry no organisation: skip the big DV issuers.
        candidates = [
            r for r in rows if not any(x in str(r.get("issuer_name", "")) for x in ("Let's Encrypt", "ZeroSSL"))
        ]
        for row in candidates[:3]:
            pem = await self._text(session, f"https://crt.sh/?d={row.get('id')}")
            if not pem or "BEGIN CERTIFICATE" not in pem:
                continue
            try:
                cert = x509.load_pem_x509_certificate(pem.encode())
                orgs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
            except ValueError:
                continue
            if orgs:
                org = str(orgs[0].value).strip()
                return None if is_generic_org(org) else org
        return None

    async def _certificate_siblings(self, session: HttpClient, org: str) -> list[str]:
        try:
            async with session.get(f"https://crt.sh/?O={quote(org)}&output=json") as resp:
                rows = await resp.json(content_type=None) if resp.status == 200 else []
        except Exception as exc:
            self.report_error("crt.sh", exc)
            return []
        names: list[str] = []
        for row in (rows or [])[:2000]:
            names += [n.lstrip("*.") for n in str(row.get("name_value", "")).splitlines()]
        return names

    @staticmethod
    async def _dns(domain: str, rtype: str) -> list[str]:
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = 6.0
        try:
            answers = await resolver.resolve(domain, rtype)
        except (dns.exception.DNSException, OSError):
            return []
        return [str(a.to_text()).rstrip(".").lower() for a in answers]

    # ------------------------------------------------------------------ run
    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        if entity.metadata.get("out_of_scope"):
            async for item in self._impostor_cluster(entity, session):
                yield item
            return
        seed = _registrable(entity.value)
        if not seed:
            return
        own_label = split_domain(seed)[0]
        evidence: list[tuple[str, Evidence]] = []
        shared: dict[str, Entity] = {}  # the shared things themselves become graph nodes

        def hub(key: str, etype: EntityType, value: str, label: str, md: dict[str, Any]) -> Entity:
            if key not in shared:
                shared[key] = Entity.create(etype, value, label=label, source_module=self.name, depth=entity.depth + 1,
                                            metadata={**md, "out_of_scope": True, "pivot_hub": True})  # fmt: skip
            return shared[key]

        # 1. Analytics / ad / tag IDs from the archived homepage
        html = await self._archived_homepage(session, seed)
        trackers = extract_trackers(html or "")
        for tracker, product in list(trackers.items())[:5]:
            hub(f"t:{tracker}", EntityType.GENERIC, tracker, f"{product} {tracker}", {"category": "tracking_id",
                "product": product})  # fmt: skip
            found = {d for h in await self._analytics(session, tracker) if (d := _registrable(h)) and d != seed}
            evidence.extend((d, Evidence("analytics", tracker, f"same {product} ID {tracker}")) for d in sorted(found))

        # 2. Certificate organisation
        org = await self._certificate_org(session, seed)
        if org:
            hub(f"o:{org}", EntityType.ORGANIZATION, org, org, {"origin": "certificate subject (O=)"})
            found = {d for h in await self._certificate_siblings(session, org) if (d := _registrable(h)) and d != seed}
            evidence.extend(
                (d, Evidence("certificate_org", org, f"certificate issued to “{org}”")) for d in sorted(found)
            )

        # 3. Dedicated name servers
        for ns in (await self._dns(seed, "NS"))[:3]:
            if is_generic_ns(ns):
                continue
            own = _registrable(ns) == seed
            hosts = await self._shared_ns(session, ns)
            if len(hosts) > MAX_SHARED_NS:
                continue
            hub(f"n:{ns}", EntityType.DOMAIN, ns, f"Name server {ns}", {"category": "nameserver"})
            for host in hosts:
                if (d := _registrable(host)) and d != seed:
                    kind = "own_nameserver" if own else "nameserver"
                    evidence.append((d, Evidence(kind, ns, f"served by name server {ns}")))

        # 4. IP addresses shared with few other domains
        for ip in (await self._dns(seed, "A"))[:3]:
            cohosted = {d for h in await self._reverse_ip(session, ip) if (d := _registrable(h)) and d != seed}
            if not cohosted or len(cohosted) > MAX_COHOSTED:
                continue  # shared hosting or a CDN: says nothing about ownership
            hub(f"i:{ip}", EntityType.IP_ADDRESS, ip, ip, {})
            kind = "shared_ip_small" if len(cohosted) <= 5 else "shared_ip"
            evidence += [
                (d, Evidence(kind, ip, f"hosted on {ip} with {len(cohosted)} other domain(s)")) for d in cohosted
            ]

        related = combine(evidence, exclude={seed})[:MAX_RELATED]
        self.report_ok()
        used_hubs: set[str] = set()
        for rel in related:
            node = Entity.create(
                EntityType.DOMAIN,
                rel.domain,
                source_module=self.name,
                depth=entity.depth + 1,
                confidence=rel.confidence,
                metadata={
                    "out_of_scope": True,  # probably theirs, but not in the authorised scope of this scan
                    "pivot": {
                        "of": seed,
                        "confidence": rel.confidence,
                        "attribution": rel.attribution,
                        "brand_like": looks_like_brand(split_domain(rel.domain)[0], own_label),
                        "evidence": [{"kind": e.kind, "value": e.value, "detail": e.detail} for e in rel.evidence[:8]],
                    },
                },
            )
            yield node
            for e in rel.evidence:
                key = {"analytics": "t", "certificate_org": "o", "own_nameserver": "n", "nameserver": "n"}.get(
                    e.kind, "i"
                )
                hub_entity = shared.get(f"{key}:{e.value}")
                if hub_entity is None:
                    continue
                if hub_entity.id not in used_hubs:
                    used_hubs.add(hub_entity.id)
                    yield hub_entity
                    yield Relation.create(entity.id, hub_entity.id, RelationType.ASSOCIATED_WITH, label=e.detail)
                yield Relation.create(node.id, hub_entity.id, RelationType.ASSOCIATED_WITH, label=e.detail)
        entity.metadata["pivot_summary"] = {
            "trackers": sorted(trackers)[:10],
            "certificate_org": org,
            "related": len(related),
            "likely": sum(1 for r in related if r.attribution.startswith("likely")),
        }

    async def _impostor_cluster(self, impostor: Entity, session: HttpClient) -> AsyncIterator[Entity | Relation]:
        """Other domains on the impostor's server that also imitate the brand: one campaign, many lures."""
        facts = impostor.metadata["lookalike"]
        brand = split_domain(facts["of"])[0]
        siblings: dict[str, str] = {}
        for ip in (facts.get("ips") or [])[:2]:
            hosts = await self._reverse_ip(session, ip)
            if len(hosts) > 150:
                continue  # a mass-hosting address: too noisy to attribute
            for host in hosts:
                d = _registrable(host)
                if d and d not in (impostor.value, facts["of"]) and looks_like_brand(split_domain(d)[0], brand):
                    siblings.setdefault(d, ip)
        self.report_ok()
        names = sorted(siblings)[:MAX_IMPOSTOR_SIBLINGS]
        impostor.metadata["lookalike"]["cluster_size"] = len(names)
        for name in names:
            mx = [m.split()[-1] for m in await self._dns(name, "MX")]
            sibling = Entity.create(
                EntityType.DOMAIN,
                name,
                source_module=self.name,
                depth=impostor.depth + 1,
                confidence=0.8,
                metadata={
                    "out_of_scope": True,
                    "lookalike": {
                        "of": facts["of"],
                        "technique": "co-hosted",
                        "detail": f"on the same server as {facts['display']} ({siblings[name]})",
                        "display": name,
                        "verdict": "suspicious",
                        "mx": mx[:6],
                        "ns": [],
                        "ips": [siblings[name]],
                        "sensitive_keyword": False,
                        "risk": risk_score("combosquat", False, bool(mx), True, "suspicious"),
                        "cluster_of": impostor.value,
                    },
                },
            )
            yield sibling
            yield Relation.create(
                sibling.id, impostor.id, RelationType.ASSOCIATED_WITH, label="Same server (impostor cluster)"
            )
