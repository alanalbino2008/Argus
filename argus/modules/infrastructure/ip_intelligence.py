"""IP Geolocation, Autonomous System (ASN), ISP, and Reverse DNS enrichment."""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import AsyncIterator

import aiohttp
import dns.asyncresolver
import dns.resolver
import dns.reversename

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.ip_intelligence")


class IpIntelligenceModule(BaseModule):
    """Enriches IP addresses with ASN, GeoIP, hosting org, and PTR records."""

    name = "ip_intelligence"
    description = "IP Geolocation, Autonomous System (ASN), ISP, and Reverse DNS mapping"
    supported_entity_types = [EntityType.IP_ADDRESS]
    attack_techniques = ("T1590.005", "T1590.004")

    async def run(
        self,
        entity: Entity,
        session: HttpClient,
        config: ScanConfig,
    ) -> AsyncIterator[Entity | Relation]:
        ip_str = entity.value.strip()

        # Check if valid and not private / bogon
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved:
                entity.metadata["is_private"] = True
                entity.metadata["classification"] = "Internal / Private IP"
                return
        except ValueError:
            return

        # 1. Reverse DNS (PTR)
        try:
            rev_name = dns.reversename.from_address(ip_str)
            resolver = dns.asyncresolver.Resolver()
            resolver.lifetime = config.timeout_seconds
            answers = await resolver.resolve(rev_name, "PTR")
            for rdata in answers:
                ptr_val = str(rdata.target).rstrip(".")
                entity.metadata["ptr_record"] = ptr_val
                ptr_entity = Entity.create(
                    entity_type=EntityType.DOMAIN,
                    value=ptr_val,
                    label=ptr_val,
                    metadata={"reverse_dns": True},
                    source_module=self.name,
                    confidence=1.0,
                    depth=entity.depth + 1,
                )
                yield ptr_entity
                yield Relation.create(
                    source_id=entity.id,
                    target_id=ptr_entity.id,
                    rel_type=RelationType.RESOLVES_TO,
                    label="Reverse DNS (PTR)",
                )
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            pass  # no PTR record configured
        except Exception as e:
            self.report_error("dns:PTR", e)

        # 2. GeoIP & ASN lookup via ip-api.com
        try:
            api_url = f"http://ip-api.com/json/{ip_str}?fields=status,message,country,countryCode,regionName,city,lat,lon,isp,org,as,asname,query"
            timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
            async with session.get(api_url, timeout=timeout) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data.get("status") == "success":
                        entity.metadata.update(
                            {
                                "country": data.get("country"),
                                "countryCode": data.get("countryCode"),
                                "city": data.get("city"),
                                "lat": data.get("lat"),
                                "lon": data.get("lon"),
                                "isp": data.get("isp"),
                                "org": data.get("org"),
                                "as": data.get("as"),
                            }
                        )

                        # Yield ASN entity
                        as_full = data.get("as", "")
                        if as_full:
                            as_number = as_full.split()[0]
                            asn_entity = Entity.create(
                                entity_type=EntityType.ASN,
                                value=as_number,
                                label=as_full,
                                metadata={
                                    "as_name": data.get("asname"),
                                    "full_string": as_full,
                                },
                                source_module=self.name,
                                confidence=1.0,
                                depth=entity.depth + 1,
                            )
                            yield asn_entity
                            yield Relation.create(
                                source_id=entity.id,
                                target_id=asn_entity.id,
                                rel_type=RelationType.HOSTED_ON,
                                label="BGP Autonomous System",
                            )

                        # Yield Organization entity if distinct
                        org_name = data.get("org") or data.get("isp")
                        if org_name and len(org_name) > 2:
                            org_entity = Entity.create(
                                entity_type=EntityType.ORGANIZATION,
                                value=org_name,
                                label=org_name,
                                metadata={"role": "network_operator", "country": data.get("country")},
                                source_module=self.name,
                                confidence=0.9,
                                depth=entity.depth + 1,
                            )
                            yield org_entity
                            yield Relation.create(
                                source_id=org_entity.id,
                                target_id=entity.id,
                                rel_type=RelationType.OPERATES,
                                label="Operates Infrastructure",
                            )
        except Exception as e:
            logger.debug("IP enrichment error for %s: %s", ip_str, e)
