"""TLS/SSL certificate analysis, certificate chain inspection, and SAN enumeration."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import ssl
from typing import AsyncIterator, Union
import aiohttp

from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.tls_analyzer")


class TlsAnalyzerModule(BaseModule):
    """Inspects live TLS certificates on port 443, extracting issuers and SAN subdomains."""

    name = "tls_analyzer"
    description = "TLS/SSL Certificate inspection, Subject Alternative Name (SAN) discovery, and cipher analysis"
    supported_entity_types = [EntityType.DOMAIN, EntityType.SUBDOMAIN]

    async def run(
        self,
        entity: Entity,
        session: aiohttp.ClientSession,
        config: ScanConfig,
    ) -> AsyncIterator[Union[Entity, Relation]]:
        domain = entity.value.strip().lower()

        # Connect asynchronously to port 443 with TLS
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            connect_fut = asyncio.open_connection(domain, 443, ssl=ssl_ctx, server_hostname=domain)
            reader, writer = await asyncio.wait_for(connect_fut, timeout=config.timeout_seconds)
            self.report_ok()

            try:
                ssl_obj = writer.get_extra_info("ssl_object")
                if not ssl_obj:
                    return

                peercert = ssl_obj.getpeercert(binary_form=False)
                cipher = ssl_obj.cipher()
                version = ssl_obj.version()

                # Extract SANs
                sans = []
                for entry in peercert.get("subjectAltName", []):
                    if entry[0] == "DNS":
                        sans.append(entry[1])

                # Extract Issuer
                issuer_dict = dict(x[0] for x in peercert.get("issuer", []))
                issuer_org = issuer_dict.get("organizationName") or issuer_dict.get("commonName") or "Unknown CA"

                # Extract Validity
                not_before = peercert.get("notBefore")
                not_after = peercert.get("notAfter")

                # Create Certificate Entity
                cert_val = f"TLS-Cert: {domain} ({issuer_org})"
                cert_entity = Entity.create(
                    entity_type=EntityType.CERTIFICATE,
                    value=cert_val,
                    label=f"Cert: {issuer_org}",
                    metadata={
                        "issuer": issuer_org,
                        "valid_from": not_before,
                        "valid_to": not_after,
                        "sans_count": len(sans),
                        "tls_version": version,
                        "cipher": cipher[0] if cipher else "Unknown",
                    },
                    source_module=self.name,
                    confidence=1.0,
                    depth=entity.depth + 1,
                )
                yield cert_entity

                yield Relation.create(
                    source_id=entity.id,
                    target_id=cert_entity.id,
                    rel_type=RelationType.SECURED_BY,
                    label="Secured By Certificate",
                )

                # Extract and yield subdomains found in SANs
                for san in sans:
                    san_clean = san.strip().lower().lstrip("*.")
                    if san_clean.endswith(f".{domain}") and san_clean != domain:
                        sub_entity = Entity.create(
                            entity_type=EntityType.SUBDOMAIN,
                            value=san_clean,
                            label=san_clean,
                            metadata={"discovered_in": "TLS_SAN"},
                            source_module=self.name,
                            confidence=0.98,
                            depth=entity.depth + 1,
                        )
                        yield sub_entity
                        yield Relation.create(
                            source_id=sub_entity.id,
                            target_id=entity.id,
                            rel_type=RelationType.SUBDOMAIN_OF,
                            label="SAN Subdomain",
                        )

            finally:
                writer.close()
                await writer.wait_closed()

        except ConnectionRefusedError:
            self.report_ok()  # port 443 closed: a valid finding, not a failure
        except Exception as e:
            logger.debug("TLS connection error for %s: %s", domain, e)
            self.report_error("tls:443", e)
