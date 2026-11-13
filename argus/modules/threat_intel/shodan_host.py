"""Shodan host API: banners, products and versions per open port (requires ARGUS_SHODAN_API_KEY).

Richer than the free InternetDB lookup: identifies the *software and version*
behind each port, which is what makes a CVE actually exploitable.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import ClassVar

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule
from argus.security.network import is_public_ip

API = "https://api.shodan.io"
MAX_SERVICES = 20


class ShodanHostModule(BaseModule):
    name = "shodan_host"
    description = "Shodan host API: services, product versions, vulnerabilities and hostnames for an IP"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.IP_ADDRESS]
    attack_techniques = ("T1596.005", "T1592.002")
    requires_settings = ("shodan_api_key",)
    rate_limits: ClassVar[dict[str, float]] = {"api.shodan.io": 1.1}  # 1 request/second

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        ip = entity.value.strip()
        try:
            if not is_public_ip(ip):
                return  # never disclose internal addresses to a third party
        except ValueError:
            return
        # Shodan only accepts the key as a query parameter; it is registered for redaction.
        url = f"{API}/shodan/host/{ip}?key={self.secret('shodan_api_key')}"
        async with session.get(url) as resp:
            if resp.status == 404:
                return  # Shodan has no data for this IP
            if resp.status != 200:
                self.report_error("shodan", f"HTTP {resp.status}")
                return
            host = await resp.json()

        entity.metadata.update(
            {
                "shodan_org": host.get("org"),
                "shodan_isp": host.get("isp"),
                "shodan_os": host.get("os"),
                "shodan_last_update": host.get("last_update"),
            }
        )

        for service in host.get("data", [])[:MAX_SERVICES]:
            port = service.get("port")
            if not isinstance(port, int):
                continue
            product = service.get("product")
            version = service.get("version")
            port_entity = Entity.create(
                entity_type=EntityType.PORT,
                value=f"{ip}:{port}",
                label=f"Port {port}" + (f" ({product})" if product else ""),
                metadata={
                    "port_number": port,
                    "transport": service.get("transport"),
                    "product": product,
                    "version": version,
                    "ip": ip,
                },
                source_module=self.name,
                confidence=0.98,
                depth=entity.depth + 1,
            )
            yield port_entity
            yield Relation.create(entity.id, port_entity.id, RelationType.EXPOSES, label=f"Exposes Port {port}")
            if product:
                tech_value = f"{product} {version}".strip() if version else product
                tech = Entity.create(
                    entity_type=EntityType.TECHNOLOGY,
                    value=tech_value,
                    label=tech_value,
                    metadata={"category": "Network Service", "source": "shodan"},
                    source_module=self.name,
                    confidence=0.9,
                    depth=entity.depth + 1,
                )
                yield tech
                yield Relation.create(port_entity.id, tech.id, RelationType.USES_TECH, label="Runs")

        for cve in sorted(host.get("vulns") or [])[:15]:
            vuln = Entity.create(
                entity_type=EntityType.VULNERABILITY,
                value=cve,
                label=cve,
                metadata={"cve_id": cve, "ip": ip, "source": "Shodan"},
                source_module=self.name,
                confidence=0.9,
                depth=entity.depth + 1,
            )
            yield vuln
            yield Relation.create(entity.id, vuln.id, RelationType.EXPOSES, label="Vulnerable to")

        for hostname in (host.get("hostnames") or [])[:5]:
            domain = Entity.create(
                entity_type=EntityType.DOMAIN,
                value=hostname.lower(),
                label=hostname.lower(),
                metadata={"discovered_via": "shodan_hostnames"},
                source_module=self.name,
                confidence=0.95,
                depth=entity.depth + 1,
            )
            yield domain
            yield Relation.create(entity.id, domain.id, RelationType.RESOLVES_TO, label="Shodan Hostname")
