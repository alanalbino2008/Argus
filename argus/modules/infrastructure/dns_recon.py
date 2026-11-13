"""DNS interrogation, record mapping, and SPF/DMARC posture analysis."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator

import dns.asyncresolver
import dns.resolver

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.module.dns_recon")


class DnsReconModule(BaseModule):
    """Interrogates DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA, DMARC) for domains."""

    name = "dns_recon"
    description = "Comprehensive DNS interrogation, mail exchange mapping, and email security verification"
    supported_entity_types = [EntityType.DOMAIN, EntityType.SUBDOMAIN]
    attack_techniques = ("T1590.002", "T1596.001")

    RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]

    async def run(
        self,
        entity: Entity,
        session: HttpClient,
        config: ScanConfig,
    ) -> AsyncIterator[Entity | Relation]:
        domain = entity.value.strip().lower()
        resolver = dns.asyncresolver.Resolver()
        resolver.lifetime = config.timeout_seconds

        spf_record: str | None = None
        txt_answered = False

        # Query standard records
        for rtype in self.RECORD_TYPES:
            try:
                answers = await resolver.resolve(domain, rtype)
                self.report_ok()
                txt_answered = txt_answered or rtype == "TXT"
                for rdata in answers:
                    text_val = rdata.to_text().strip('"')

                    if rtype in ("A", "AAAA"):
                        ip_entity = Entity.create(
                            entity_type=EntityType.IP_ADDRESS,
                            value=text_val,
                            label=text_val,
                            metadata={"record_type": rtype, "domain": domain},
                            source_module=self.name,
                            confidence=1.0,
                            depth=entity.depth + 1,
                        )
                        yield ip_entity
                        yield Relation.create(
                            source_id=entity.id,
                            target_id=ip_entity.id,
                            rel_type=RelationType.RESOLVES_TO,
                            label=f"DNS {rtype}",
                        )

                    elif rtype == "MX":
                        # MX records have priority and exchange host
                        parts = text_val.split()
                        mx_host = parts[-1].rstrip(".")
                        mx_entity = Entity.create(
                            entity_type=EntityType.DOMAIN,
                            value=mx_host,
                            label=f"MX: {mx_host}",
                            metadata={"priority": parts[0] if len(parts) > 1 else 0},
                            source_module=self.name,
                            confidence=0.95,
                            depth=entity.depth + 1,
                        )
                        yield mx_entity
                        yield Relation.create(
                            source_id=entity.id,
                            target_id=mx_entity.id,
                            rel_type=RelationType.ASSOCIATED_WITH,
                            label="Mail Server",
                        )

                    elif rtype == "NS":
                        ns_host = text_val.rstrip(".")
                        ns_entity = Entity.create(
                            entity_type=EntityType.DOMAIN,
                            value=ns_host,
                            label=f"NS: {ns_host}",
                            metadata={"role": "authoritative_nameserver"},
                            source_module=self.name,
                            confidence=0.95,
                            depth=entity.depth + 1,
                        )
                        yield ns_entity
                        yield Relation.create(
                            source_id=entity.id,
                            target_id=ns_entity.id,
                            rel_type=RelationType.ASSOCIATED_WITH,
                            label="Authoritative Nameserver",
                        )

                    elif rtype == "CNAME":
                        target_cname = text_val.rstrip(".")
                        cname_entity = Entity.create(
                            entity_type=EntityType.DOMAIN,
                            value=target_cname,
                            label=target_cname,
                            metadata={"cname_target": True},
                            source_module=self.name,
                            confidence=0.95,
                            depth=entity.depth + 1,
                        )
                        yield cname_entity
                        yield Relation.create(
                            source_id=entity.id,
                            target_id=cname_entity.id,
                            rel_type=RelationType.RESOLVES_TO,
                            label="CNAME Alias",
                        )

                    elif rtype == "TXT" and "v=spf1" in text_val.lower():  # SPF policy
                        spf_record = text_val
                        rec_entity = Entity.create(
                            entity_type=EntityType.DNS_RECORD,
                            value=f"SPF: {text_val[:80]}...",
                            label="SPF Policy",
                            metadata={"full_record": text_val, "type": "SPF"},
                            source_module=self.name,
                            confidence=1.0,
                            depth=entity.depth + 1,
                        )
                        yield rec_entity
                        yield Relation.create(
                            source_id=entity.id,
                            target_id=rec_entity.id,
                            rel_type=RelationType.HAS_DNS_RECORD,
                            label="SPF Record",
                        )

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):  # noqa: PERF203 - isolate each record type
                self.report_ok()  # authoritative "no such record" is a valid answer
                continue
            except Exception as e:
                logger.debug("DNS query %s for %s error: %s", rtype, domain, e)
                self.report_error(f"dns:{rtype}", e)

        # Query DMARC policy. Three-valued on purpose: "missing" (authoritative answer: none
        # published) must never be confused with "unknown" (the lookup failed).
        dmarc_policy = "unknown"
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = await resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                text_val = rdata.to_text().strip('"')
                if "v=dmarc1" in text_val.lower():
                    dmarc_policy = _dmarc_policy(text_val)
                    dmarc_entity = Entity.create(
                        entity_type=EntityType.DNS_RECORD,
                        value=f"DMARC: {text_val[:80]}...",
                        label="DMARC Policy",
                        metadata={"full_record": text_val, "type": "DMARC"},
                        source_module=self.name,
                        confidence=1.0,
                        depth=entity.depth + 1,
                    )
                    yield dmarc_entity
                    yield Relation.create(
                        source_id=entity.id,
                        target_id=dmarc_entity.id,
                        rel_type=RelationType.HAS_DNS_RECORD,
                        label="DMARC Record",
                    )
            if dmarc_policy == "unknown":
                dmarc_policy = "missing"  # TXT records exist but none is DMARC
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            dmarc_policy = "missing"
        except Exception as e:
            self.report_error("dns:DMARC", e)

        # Facts other components reason over (e.g. the attack path engine), set on the domain itself.
        entity.metadata["dns_checked"] = True
        entity.metadata["dmarc_policy"] = dmarc_policy
        entity.metadata["spf"] = spf_record or ("missing" if txt_answered else "unknown")


def _dmarc_policy(record: str) -> str:
    """Extract the p= tag: "reject", "quarantine" or "none" ("none" also if malformed)."""
    for tag in record.split(";"):
        key, _, value = tag.strip().partition("=")
        if key.strip().lower() == "p":
            policy = value.strip().lower()
            return policy if policy in ("reject", "quarantine", "none") else "none"
    return "none"
