"""Shodan InternetDB passive exposure, open port, and CVE vulnerability intelligence."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

import aiohttp

from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.shodan_internetdb")


class ShodanInternetDbModule(BaseModule):
    """Interrogates Shodan's free InternetDB passive endpoint for open ports, tags, and CVEs."""

    name = "shodan_internetdb"
    description = "Passive open port discovery, service tags, and known CVE vulnerability mapping via Shodan"
    supported_entity_types = [EntityType.IP_ADDRESS]

    PORT_SERVICE_MAP = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        6379: "Redis",
        8080: "HTTP-Proxy/Alt",
        8443: "HTTPS-Alt",
        9200: "Elasticsearch",
        27017: "MongoDB",
    }

    async def run(
        self,
        entity: Entity,
        session: aiohttp.ClientSession,
        config: ScanConfig,
    ) -> AsyncIterator[Entity | Relation]:
        ip = entity.value.strip()

        # Skip private IPs
        if entity.metadata.get("is_private"):
            return

        api_url = f"https://internetdb.shodan.io/{ip}"
        headers = {"User-Agent": "Argus-OSINT/1.0 (Threat-Exposure-Audit)"}

        try:
            timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
            async with session.get(api_url, headers=headers, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()

                    ports = data.get("ports", [])
                    cves = data.get("cves", [])
                    tags = data.get("tags", [])
                    hostnames = data.get("hostnames", [])

                    entity.metadata["shodan_open_ports"] = ports
                    entity.metadata["shodan_cves"] = cves
                    entity.metadata["shodan_tags"] = tags

                    # 1. Open Ports
                    for port_num in ports[:12]:  # Top 12 ports to avoid graph clutter
                        svc_name = self.PORT_SERVICE_MAP.get(port_num, "Service")
                        port_entity = Entity.create(
                            entity_type=EntityType.PORT,
                            value=f"{ip}:{port_num}",
                            label=f"Port {port_num} ({svc_name})",
                            metadata={
                                "port_number": port_num,
                                "service_guess": svc_name,
                                "ip": ip,
                            },
                            source_module=self.name,
                            confidence=0.98,
                            depth=entity.depth + 1,
                        )
                        yield port_entity
                        yield Relation.create(
                            source_id=entity.id,
                            target_id=port_entity.id,
                            rel_type=RelationType.EXPOSES,
                            label=f"Exposes Port {port_num}",
                        )

                    # 2. Known CVE Vulnerabilities
                    for cve_id in cves[:8]:
                        vuln_entity = Entity.create(
                            entity_type=EntityType.VULNERABILITY,
                            value=cve_id,
                            label=cve_id,
                            metadata={"cve_id": cve_id, "ip": ip, "source": "Shodan InternetDB"},
                            source_module=self.name,
                            confidence=0.95,
                            depth=entity.depth + 1,
                        )
                        yield vuln_entity
                        yield Relation.create(
                            source_id=entity.id,
                            target_id=vuln_entity.id,
                            rel_type=RelationType.EXPOSES,
                            label="Vulnerable to",
                        )

                    # 3. Discovered Hostnames / PTR
                    for host in hostnames[:5]:
                        host_clean = host.strip().lower()
                        if host_clean:
                            host_entity = Entity.create(
                                entity_type=EntityType.DOMAIN,
                                value=host_clean,
                                label=host_clean,
                                metadata={"discovered_via": "shodan_hostnames"},
                                source_module=self.name,
                                confidence=0.95,
                                depth=entity.depth + 1,
                            )
                            yield host_entity
                            yield Relation.create(
                                source_id=entity.id,
                                target_id=host_entity.id,
                                rel_type=RelationType.RESOLVES_TO,
                                label="Shodan Hostname",
                            )

        except Exception as e:
            logger.debug("Shodan InternetDB lookup failed for %s: %s", ip, e)
