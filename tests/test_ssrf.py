"""Egress guard (SSRF protection) tests."""

import aiohttp
import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from argus.core.engine import ArgusEngine
from argus.core.events import EventBus
from argus.core.http import HttpClient
from argus.core.models import EntityType, ScanConfig
from argus.modules.base import BaseModule
from argus.security.network import (
    BlockedDestinationError,
    GuardedResolver,
    is_public_ip,
    resolve_public,
    validate_scan_target,
)


@pytest.mark.parametrize(
    "ip,public",
    [
        ("8.8.8.8", True),
        ("2606:4700::1111", True),
        ("10.1.2.3", False),
        ("172.16.0.1", False),
        ("192.168.1.1", False),
        ("127.0.0.1", False),
        ("169.254.169.254", False),  # cloud metadata service
        ("100.64.0.1", False),  # carrier-grade NAT
        ("0.0.0.0", False),
        ("224.0.0.1", False),
        ("::1", False),
        ("fd00::1", False),
        ("::ffff:127.0.0.1", False),  # IPv4-mapped loopback bypass attempt
    ],
)
def test_ip_classification(ip, public):
    assert is_public_ip(ip) is public


@pytest.mark.parametrize(
    "target,etype",
    [
        ("127.0.0.1", EntityType.IP_ADDRESS),
        ("169.254.169.254", EntityType.IP_ADDRESS),
        ("localhost", EntityType.DOMAIN),
        ("db.internal", EntityType.DOMAIN),
        ("printer.local", EntityType.DOMAIN),
        ("admin@intranet.corp", EntityType.EMAIL),
    ],
)
def test_internal_seed_targets_rejected(target, etype):
    with pytest.raises(ValueError, match=r"internal|private"):
        validate_scan_target(target, etype)


@pytest.mark.parametrize(
    "target,etype",
    [
        ("example.com", EntityType.DOMAIN),
        ("8.8.8.8", EntityType.IP_ADDRESS),
        ("user@example.com", EntityType.EMAIL),
        ("johndoe", EntityType.USERNAME),
    ],
)
def test_public_seed_targets_allowed(target, etype):
    validate_scan_target(target, etype)


class FakeResolver:
    """Pretends DNS answers - lets us simulate DNS-rebinding without the network."""

    def __init__(self, answers):
        self.answers = answers

    async def resolve(self, host, port=0, family=0):
        return [
            {"hostname": host, "host": ip, "port": port, "family": family, "proto": 0, "flags": 0}
            for ip in self.answers[host]
        ]

    async def close(self):
        pass


async def test_resolver_blocks_public_name_pointing_at_private_ip():
    resolver = GuardedResolver(FakeResolver({"evil.example": ["10.0.0.5"]}))
    with pytest.raises(BlockedDestinationError):
        await resolver.resolve("evil.example", 80)


async def test_resolver_filters_mixed_answers_to_public_only():
    resolver = GuardedResolver(FakeResolver({"mixed.example": ["127.0.0.1", "93.184.216.34"]}))
    assert [r["host"] for r in await resolver.resolve("mixed.example", 80)] == ["93.184.216.34"]


async def test_resolver_trusts_configured_proxy_only():
    inner = FakeResolver({"proxy.corp": ["10.0.0.9"]})
    assert await GuardedResolver(inner, trusted_hosts=["proxy.corp"]).resolve("proxy.corp", 3128)
    with pytest.raises(BlockedDestinationError):
        await GuardedResolver(inner).resolve("proxy.corp", 3128)


async def test_resolve_public_rejects_ip_literals():
    with pytest.raises(BlockedDestinationError):
        await resolve_public("169.254.169.254", 443)


async def test_http_client_blocks_without_sending_request():
    hits = []

    async def handler(request):
        hits.append(1)
        return web.Response(text="secret")

    app = web.Application()
    app.router.add_get("/", handler)
    server = TestServer(app)
    await server.start_server()
    try:
        async with aiohttp.ClientSession() as s:
            client = HttpClient(s, max_retries=3)  # default: private destinations blocked
            with pytest.raises(BlockedDestinationError):
                async with client.get(str(server.make_url("/"))):
                    pass
        assert hits == [] and client.stats.blocked == 1 and client.stats.retries == 0
    finally:
        await server.close()


async def test_engine_blocks_module_reaching_cloud_metadata():
    class MetadataThief(BaseModule):
        name = "metadata_thief"
        supported_entity_types = [EntityType.DOMAIN]

        async def run(self, entity, session, config):
            try:
                async with session.get("http://169.254.169.254/latest/meta-data/iam/"):
                    pass
            except BlockedDestinationError:
                pass  # modules swallow errors - the run report still records it
            return
            yield  # pragma: no cover

    config = ScanConfig(target="example.com", target_type=EntityType.DOMAIN, max_depth=0)
    engine = ArgusEngine(config, bus=EventBus(), modules={"metadata_thief": MetadataThief()})
    await engine.start()
    assert engine.http.stats.blocked == 1
    assert engine.http.stats.requests == 0
    assert engine.module_stats["metadata_thief"].failed == 1
