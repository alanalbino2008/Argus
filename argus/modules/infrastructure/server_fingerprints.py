"""Server fingerprints that cluster infrastructure: JARM for TLS servers, HASSH for SSH servers.

Both turn *how a server is configured* into a hash. Hosts with the same hash are linked through
one shared node, the same way favicons are. That exposes a command-and-control framework's
servers, a phishing kit's hosting, or an organisation's own estate set up from one template. The
node carries ready-made searches to find the rest of the internet with that hash.

Both are active (they talk to the target's servers) and use raw sockets, so routed scans skip
them, and they only ever connect to vetted public addresses. A shared hash is a lead, not
proof: popular default configurations (a CDN's TLS stack, a stock OpenSSH) are shared by
countless unrelated servers, so the relations carry low confidence.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from typing import ClassVar

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, RelationType, ScanConfig
from argus.intel import cenql, ssh_fingerprint
from argus.intel import jarm as jarm_intel
from argus.modules.base import BaseModule
from argus.security.network import BlockedDestinationError, resolve_public

logger = logging.getLogger("argus.module.server_fingerprints")

TLS_PORTS = frozenset({443, 4443, 8443, 9443, 10443})
SSH_PORTS = frozenset({22, 2222, 22222})
SHARED_FINGERPRINT_CONFIDENCE = 0.5
PROBE_TIMEOUT = 6.0


def _port_of(entity: Entity) -> int | None:
    number = entity.metadata.get("port_number")
    if isinstance(number, int):
        return number
    _, _, tail = entity.value.rpartition(":")
    return int(tail) if tail.isdigit() else None


def _host_of(entity: Entity) -> str:
    if entity.type == EntityType.PORT:
        return str(entity.metadata.get("ip") or entity.value.rpartition(":")[0]).strip("[]")
    return entity.value.strip().lower().rstrip(".")


class _FingerprintModule(BaseModule):
    active = True
    direct_connections = True

    async def _address(self, host: str, port: int, config: ScanConfig) -> str | None:
        """A vetted public address to connect to (never the name, so DNS can't be re-pointed)."""
        if config.allow_private_targets:
            return host
        try:
            return (await resolve_public(host, port))[0]
        except BlockedDestinationError:
            return None  # private or reserved: never contacted
        except OSError as exc:
            self.report_error(f"dns:{host}", exc)
            return None


class JarmModule(_FingerprintModule):
    name = "jarm"
    description = "JARM active TLS fingerprinting: links servers configured the same way (Shodan/Censys searchable)"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.DOMAIN, EntityType.SUBDOMAIN, EntityType.PORT]
    attack_techniques = ("T1595", "T1596.005")
    timeout_factor = 2.0  # ten handshakes, one after another

    def can_handle(self, entity: Entity) -> bool:
        if entity.metadata.get("out_of_scope") or entity.type not in self.supported_entity_types:
            return False
        return entity.type != EntityType.PORT or _port_of(entity) in TLS_PORTS

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        host = _host_of(entity)
        port = _port_of(entity) if entity.type == EntityType.PORT else 443
        if not host or port is None:
            return
        address = await self._address(host, port, config)
        if address is None:
            return
        result = await jarm_intel.fingerprint(address, port, host, timeout=min(PROBE_TIMEOUT, config.timeout_seconds))
        self.report_ok()
        digest = str(result["jarm"])
        if digest == jarm_intel.ZERO_JARM:
            return  # no TLS on this port
        node = Entity.create(
            EntityType.GENERIC,
            f"jarm:{digest}",
            label=f"JARM {digest[:12]}…",
            source_module=self.name,
            depth=entity.depth + 1,
            metadata={
                "category": "jarm",
                "jarm": digest,
                "probes_answered": result["answered"],
                "pivot_hub": True,
                "search_queries": {"shodan": f"ssl.jarm:{digest}", "censys": cenql.jarm(digest)},
            },
        )
        yield node
        yield Relation.create(
            entity.id, node.id, RelationType.USES_TECH, label="TLS fingerprint",
            metadata={"port": port}, confidence=SHARED_FINGERPRINT_CONFIDENCE,
        )  # fmt: skip


class SshFingerprintModule(_FingerprintModule):
    name = "ssh_fingerprint"
    description = "SSH banner and HASSH-server fingerprint (no login attempt): links identically built SSH servers"
    supported_entity_types: ClassVar[list[EntityType]] = [EntityType.PORT]
    attack_techniques = ("T1595", "T1592.002")

    def can_handle(self, entity: Entity) -> bool:
        if entity.type != EntityType.PORT or entity.metadata.get("out_of_scope"):
            return False
        guess = str(entity.metadata.get("service_guess", "")).lower()
        return _port_of(entity) in SSH_PORTS or "ssh" in guess

    async def run(self, entity: Entity, session: HttpClient, config: ScanConfig) -> AsyncIterator[Entity | Relation]:
        host, port = _host_of(entity), _port_of(entity)
        if not host or port is None:
            return
        address = await self._address(host, port, config)
        if address is None:
            return
        try:
            info = await ssh_fingerprint.fingerprint(address, port, timeout=min(PROBE_TIMEOUT, config.timeout_seconds))
        except ConnectionRefusedError:
            self.report_ok()  # closed now: a finding, not a failure
            return
        except (OSError, asyncio.TimeoutError, ssh_fingerprint.SshProtocolError) as exc:
            self.report_error(f"ssh:{port}", exc)
            return
        self.report_ok()
        digest = info["hassh_server"]
        node = Entity.create(
            EntityType.GENERIC,
            f"hassh:{digest}",
            label=f"HASSH {digest[:12]}…",
            source_module=self.name,
            depth=entity.depth + 1,
            metadata={
                "category": "hassh",
                "hassh_server": digest,
                "hassh_server_algorithms": info["hassh_server_algorithms"],
                "pivot_hub": True,
                "search_queries": {"shodan": f"ssh.hassh:{digest}", "censys": cenql.hassh(digest)},
            },
        )
        yield node
        yield Relation.create(
            entity.id, node.id, RelationType.USES_TECH, label="SSH fingerprint",
            metadata={"banner": info["banner"]}, confidence=SHARED_FINGERPRINT_CONFIDENCE,
        )  # fmt: skip
        if info["software"]:
            software = Entity.create(
                EntityType.TECHNOLOGY,
                info["software"].replace("_", " ", 1),
                source_module=self.name,
                depth=entity.depth + 1,
                metadata={
                    "category": "SSH Server",
                    "banner": info["banner"],
                    "host_key_algorithms": info["host_key_algorithms"][:12],
                },
            )
            yield software
            yield Relation.create(entity.id, software.id, RelationType.USES_TECH, label="runs")
