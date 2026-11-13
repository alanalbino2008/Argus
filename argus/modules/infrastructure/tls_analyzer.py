"""TLS/SSL certificate analysis and SAN enumeration.

Certificate verification is deliberately disabled so that *any* certificate can be
inspected - self-signed, expired and mismatched certificates are findings, not
errors. Because of that, ``SSLSocket.getpeercert()`` returns an empty dict (Python
only decodes *verified* certificates), so the raw DER bytes are parsed with
``cryptography`` instead.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule
from argus.security.network import resolve_public

logger = logging.getLogger("argus.module.tls_analyzer")


def _name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str | None:
    attrs = name.get_attributes_for_oid(oid)
    return str(attrs[0].value) if attrs else None


def parse_certificate(der: bytes, now: datetime | None = None) -> dict[str, Any]:
    """Extract investigator-relevant facts from a DER-encoded X.509 certificate."""
    cert = x509.load_der_x509_certificate(der)
    now = now or datetime.now(timezone.utc)
    not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key = f"RSA-{public_key.key_size}"
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key = f"EC-{public_key.curve.name}"
    else:
        key = type(public_key).__name__

    issuer_org = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = _name_attr(cert.issuer, NameOID.COMMON_NAME)
    sig_hash = cert.signature_hash_algorithm
    return {
        "subject_cn": _name_attr(cert.subject, NameOID.COMMON_NAME),
        "issuer": issuer_org or issuer_cn or "Unknown CA",
        "issuer_cn": issuer_cn,
        "self_signed": cert.issuer == cert.subject,
        "serial": format(cert.serial_number, "x"),
        "sha256_fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "valid_from": not_before.isoformat(),
        "valid_to": not_after.isoformat(),
        "days_remaining": (not_after - now).days,
        "expired": now > not_after,
        "not_yet_valid": now < not_before,
        "sans": sans,
        "public_key": key,
        "signature_hash": sig_hash.name if sig_hash else None,
    }


class TlsAnalyzerModule(BaseModule):
    """Inspects live TLS certificates, extracting issuer, validity and SAN subdomains."""

    name = "tls_analyzer"
    description = "TLS/SSL Certificate inspection, Subject Alternative Name (SAN) discovery, and cipher analysis"
    supported_entity_types = [EntityType.DOMAIN, EntityType.SUBDOMAIN]
    port = 443

    async def run(
        self,
        entity: Entity,
        session: HttpClient,
        config: ScanConfig,
    ) -> AsyncIterator[Entity | Relation]:
        domain = entity.value.strip().lower()

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE  # inspect any certificate; validity is reported, not enforced

        try:
            # Connect to a vetted public IP (not the name) so DNS cannot be re-pointed
            # at an internal address between the check and the connection.
            connect_host = domain if config.allow_private_targets else (await resolve_public(domain, self.port))[0]
            connect_fut = asyncio.open_connection(connect_host, self.port, ssl=ssl_ctx, server_hostname=domain)
            _reader, writer = await asyncio.wait_for(connect_fut, timeout=config.timeout_seconds)
            self.report_ok()
        except ConnectionRefusedError:
            self.report_ok()  # port closed: a valid finding, not a failure
            return
        except Exception as e:
            logger.debug("TLS connection error for %s: %s", domain, e)
            self.report_error(f"tls:{self.port}", e)
            return

        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            if not der:
                return
            cipher = ssl_obj.cipher()
            tls_version = ssl_obj.version()
        finally:
            writer.close()
            # Peers often reset TLS connections on close; there is nothing to recover.
            with contextlib.suppress(ssl.SSLError, ConnectionError, OSError):
                await writer.wait_closed()

        try:
            info = parse_certificate(der)
        except ValueError as e:
            self.report_error("tls:parse", e)
            return

        cert_entity = Entity.create(
            entity_type=EntityType.CERTIFICATE,
            value=f"TLS-Cert: {info['sha256_fingerprint']}",
            label=f"Cert: {info['issuer']}",
            metadata={
                **{k: v for k, v in info.items() if k != "sans"},
                "observed_on": domain,
                "sans_count": len(info["sans"]),
                "tls_version": tls_version,
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

        for san in info["sans"]:
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
