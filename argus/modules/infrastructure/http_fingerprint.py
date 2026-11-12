"""HTTP technology fingerprinting, server header analysis, and security posture grading."""

from __future__ import annotations

import logging
from typing import AsyncIterator, Dict, List, Tuple, Union
import aiohttp

from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.http_fingerprint")


class HttpFingerprintModule(BaseModule):
    """Passively fingerprints web servers, web frameworks, CDNs, and security headers."""

    name = "http_fingerprint"
    description = "Web technology fingerprinting, CDN detection, and HTTP security header compliance auditing"
    supported_entity_types = [EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.IP_ADDRESS]

    SECURITY_HEADERS = [
        "strict-transport-security",
        "content-security-policy",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
    ]

    async def run(
        self,
        entity: Entity,
        session: aiohttp.ClientSession,
        config: ScanConfig,
    ) -> AsyncIterator[Union[Entity, Relation]]:
        target = entity.value.strip()
        protocol = "http" if entity.type == EntityType.IP_ADDRESS else "https"
        url = f"{protocol}://{target}"

        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ArgusOSINT/1.0 (Security Recon)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        try:
            timeout = aiohttp.ClientTimeout(total=config.timeout_seconds)
            async with session.get(url, headers=headers, timeout=timeout, allow_redirects=True, ssl=False) as resp:
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                tech_stack: List[Tuple[str, str]] = []  # (Tech Name, Category)

                # 1. Server Header
                server = resp_headers.get("server")
                if server:
                    tech_stack.append((server, "Web Server"))

                # 2. X-Powered-By
                powered = resp_headers.get("x-powered-by")
                if powered:
                    tech_stack.append((powered, "Application Framework"))

                # 3. CDN & Cloud Detection
                if "cf-ray" in resp_headers or "cloudflare" in str(server).lower():
                    tech_stack.append(("Cloudflare CDN & WAF", "CDN / Proxy"))
                if "x-amz-cf-id" in resp_headers:
                    tech_stack.append(("Amazon CloudFront", "CDN"))
                if "x-azure-ref" in resp_headers:
                    tech_stack.append(("Microsoft Azure CDN", "CDN"))
                if "x-goog-generation" in resp_headers:
                    tech_stack.append(("Google Cloud Storage", "Cloud Host"))

                # 4. Security Header Audit & Grade
                present_sec_headers = {}
                missing_sec_headers = []
                score = 0

                for sh in self.SECURITY_HEADERS:
                    if sh in resp_headers:
                        present_sec_headers[sh] = resp_headers[sh]
                        score += 1
                    else:
                        missing_sec_headers.append(sh)

                # Compute Grade (A: 5-6, B: 4, C: 3, D: 2, F: 0-1)
                if score >= 5:
                    grade = "A"
                elif score == 4:
                    grade = "B"
                elif score == 3:
                    grade = "C"
                elif score == 2:
                    grade = "D"
                else:
                    grade = "F"

                entity.metadata["security_headers_grade"] = grade
                entity.metadata["present_security_headers"] = present_sec_headers
                entity.metadata["missing_security_headers"] = missing_sec_headers
                entity.metadata["http_status"] = resp.status

                # Yield discovered technologies
                for tech_name, category in tech_stack:
                    tech_entity = Entity.create(
                        entity_type=EntityType.TECHNOLOGY,
                        value=tech_name,
                        label=tech_name,
                        metadata={"category": category, "target": target},
                        source_module=self.name,
                        confidence=0.95,
                        depth=entity.depth + 1,
                    )
                    yield tech_entity

                    yield Relation.create(
                        source_id=entity.id,
                        target_id=tech_entity.id,
                        rel_type=RelationType.USES_TECH,
                        label=f"Uses {category}",
                    )

        except Exception as e:
            logger.debug("HTTP fingerprinting failed for %s: %s", target, e)
