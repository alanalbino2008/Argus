"""Egress guard: stop Argus being turned against private/internal networks (SSRF).

Argus makes outbound connections to whatever a scan discovers. Without a guard,
anyone allowed to start a scan could make the *server* connect to
``169.254.169.254`` (cloud metadata credentials), ``localhost`` admin panels or
the internal network - Server-Side Request Forgery.

Defence is enforced at three points:

1. **Seed validation** (:func:`validate_scan_target`) - reject obviously internal targets up front.
2. **Connection time** (:class:`GuardedResolver`) - every hostname aiohttp resolves is
   filtered *after* DNS resolution, using the exact addresses the socket will connect
   to. This defeats DNS-rebinding tricks (a public name that resolves to 10.0.0.5).
3. **IP literals / raw sockets** (:func:`assert_public_host`) - for URLs containing an IP
   and for modules that open sockets directly (TLS analyzer).

When an outbound proxy is configured (``HTTPS_PROXY``) the proxy performs DNS for
proxied requests and is responsible for egress policy; IP-literal checks still apply.

Authorised internal assessments can opt out with ``ARGUS_ALLOW_PRIVATE_TARGETS=true``
(API) or ``--allow-private`` (CLI).
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit
from urllib.request import getproxies

from aiohttp.abc import AbstractResolver
from aiohttp.resolver import DefaultResolver

from argus.core.models import EntityType

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

# Hostnames that never resolve to the public internet.
INTERNAL_SUFFIXES = (
    "localhost",
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".corp",
    ".home.arpa",
    ".lan",
)


class BlockedDestinationError(OSError):
    """Raised when a connection would reach a private, loopback or otherwise non-public address."""


def is_public_ip(ip: str | IPAddress) -> bool:
    """True only for globally routable unicast addresses."""
    addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped  # ::ffff:127.0.0.1 must be judged as 127.0.0.1
    return addr.is_global and not addr.is_multicast


def _as_ip(host: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def is_internal_hostname(host: str) -> bool:
    h = host.lower().rstrip(".")
    return h in ("localhost",) or h.endswith(INTERNAL_SUFFIXES) or "." not in h


def assert_public_host(host: str) -> None:
    """Reject IP literals that are not public and well-known internal hostnames."""
    ip = _as_ip(host)
    if ip is not None:
        if not is_public_ip(ip):
            raise BlockedDestinationError(f"Destination {host} is not a public address")
    elif is_internal_hostname(host):
        raise BlockedDestinationError(f"Destination {host} is an internal hostname")


async def resolve_public(host: str, port: int) -> list[str]:
    """Resolve ``host`` and return only public addresses (for raw-socket modules)."""
    ip = _as_ip(host)
    if ip is not None:
        assert_public_host(host)
        return [str(ip)]
    assert_public_host(host)
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = [str(info[4][0]) for info in infos]
    public = [a for a in addresses if is_public_ip(a)]
    if not public:
        raise BlockedDestinationError(f"{host} resolves only to non-public addresses")
    return public


class GuardedResolver(AbstractResolver):
    """aiohttp resolver that drops every non-public address after DNS resolution."""

    def __init__(self, inner: AbstractResolver | None = None, trusted_hosts: Iterable[str] = ()):
        self._inner = inner or DefaultResolver()
        # The operator-configured outbound proxy may legitimately be internal.
        self._trusted = {h.lower() for h in trusted_hosts}

    async def resolve(self, host: str, port: int = 0, family: socket.AddressFamily = socket.AF_INET) -> list[Any]:
        if host.lower() in self._trusted:
            return await self._inner.resolve(host, port, family)
        assert_public_host(host)
        results = await self._inner.resolve(host, port, family)
        allowed = [r for r in results if is_public_ip(r["host"])]
        if not allowed:
            raise BlockedDestinationError(f"{host} resolves only to non-public addresses")
        return allowed

    async def close(self) -> None:
        await self._inner.close()


def configured_proxy_hosts() -> set[str]:
    """Hostnames of proxies from HTTP(S)_PROXY / ALL_PROXY (trusted by the resolver)."""
    hosts = set()
    for scheme, url in getproxies().items():
        if scheme == "no":
            continue
        host = urlsplit(url if "://" in url else f"http://{url}").hostname
        if host:
            hosts.add(host.lower())
    return hosts


def validate_scan_target(target: str, target_type: EntityType) -> None:
    """Reject seed targets that point at private infrastructure. Raises ValueError."""
    t = target.strip()
    if target_type == EntityType.IP_ADDRESS:
        ip = _as_ip(t)
        if ip is None:
            raise ValueError(f"'{t}' is not a valid IP address")
        if not is_public_ip(ip):
            raise ValueError(f"{t} is a private/reserved address; scanning internal networks is disabled")
    elif target_type in (EntityType.DOMAIN, EntityType.SUBDOMAIN):
        if is_internal_hostname(t):
            raise ValueError(f"{t} is an internal hostname; scanning internal networks is disabled")
    elif target_type == EntityType.EMAIL and "@" in t:
        domain = t.rsplit("@", 1)[1]
        if is_internal_hostname(domain) or (_as_ip(domain) is not None and not is_public_ip(domain)):
            raise ValueError(f"{domain} is internal; scanning internal networks is disabled")
