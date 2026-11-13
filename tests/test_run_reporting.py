"""Module run outcome classification: success / degraded / failed."""

import pytest
from aiohttp import web
from aiohttp.test_utils import TestServer

from argus.core.engine import ArgusEngine
from argus.core.events import EventBus
from argus.core.models import Entity, EntityType, ScanConfig
from argus.core.runctx import ModuleRunReport, report_error
from argus.modules.base import BaseModule
from tests.test_engine import FanOutModule


def test_report_outcomes():
    r = ModuleRunReport("m", "e")
    assert r.outcome == "success"
    r.record_error("crt.sh", TimeoutError("slow"))
    assert r.outcome == "failed"
    r.record_ok()
    assert r.outcome == "degraded"
    assert r.errors == ["crt.sh: TimeoutError: slow"]


def test_report_error_outside_run_is_noop():
    report_error("anywhere", "boom")  # must not raise


class SilentlyBrokenModule(BaseModule):
    """Mimics a real module: swallows its source error and yields nothing."""

    name = "silently_broken"
    supported_entity_types = [EntityType.SUBDOMAIN]

    async def run(self, entity, session, config):
        try:
            raise ConnectionError("source unreachable")
        except ConnectionError as exc:
            self.report_error("example-source", exc)
        return
        yield  # pragma: no cover


class PartlyBrokenModule(BaseModule):
    """One source fails, another answers."""

    name = "partly_broken"
    supported_entity_types = [EntityType.DOMAIN]

    async def run(self, entity, session, config):
        self.report_error("source-a", "HTTP 503")
        self.report_ok()
        return
        yield  # pragma: no cover


def make_engine(modules, **cfg):
    config = ScanConfig(target="example.com", target_type=EntityType.DOMAIN, **cfg)
    return ArgusEngine(config, bus=EventBus(), modules={m.name: m for m in modules})


async def test_swallowed_errors_now_count_as_failures_and_trip_breaker():
    engine = make_engine(
        [FanOutModule(fan=6), SilentlyBrokenModule()],
        max_depth=2, concurrency_limit=1, circuit_breaker_threshold=3,
    )
    await engine.start()
    stats = engine.module_stats["silently_broken"]
    assert stats.failed == 3 and stats.succeeded == 0
    assert stats.disabled is True
    assert any("all data sources failed" in e for e in engine.investigation.errors)


async def test_partial_failure_is_degraded_not_failed():
    engine = make_engine([PartlyBrokenModule()])
    await engine.start()
    stats = engine.module_stats["partly_broken"]
    assert stats.succeeded == 1 and stats.degraded == 1 and stats.failed == 0
    assert stats.source_errors == 1
    assert engine.investigation.warnings


async def test_http_failures_are_captured_automatically():
    """A module that ignores a 503 (like most real modules do) is still marked failed."""

    async def handler(request):
        return web.Response(status=503)

    app = web.Application()
    app.router.add_get("/", handler)
    server = TestServer(app)
    await server.start_server()

    class NaiveHttpModule(BaseModule):
        name = "naive_http"
        supported_entity_types = [EntityType.DOMAIN]

        async def run(self, entity, session, config):
            async with session.get(str(server.make_url("/"))) as resp:
                if resp.status == 200:  # silently ignores anything else
                    yield entity

    try:
        engine = make_engine([NaiveHttpModule()], max_retries=0)
        await engine.start()
    finally:
        await server.close()
    stats = engine.module_stats["naive_http"]
    assert stats.failed == 1 and stats.source_errors == 1
    assert "HTTP 503" in engine.investigation.errors[0]
