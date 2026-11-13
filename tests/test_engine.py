"""Engine behaviour tests using fake in-memory modules (no network access)."""

import asyncio
import time

from argus.core.engine import ArgusEngine
from argus.core.events import EventBus, EventType
from argus.core.models import Entity, EntityType, InvestigationStatus, Relation, RelationType, ScanConfig
from argus.modules.base import BaseModule


def child(parent: Entity, value: str, module: str) -> Entity:
    return Entity.create(
        entity_type=EntityType.SUBDOMAIN,
        value=value,
        label=value,
        source_module=module,
        depth=parent.depth + 1,
    )


class FanOutModule(BaseModule):
    """Every domain/subdomain yields `fan` children, with an optional delay."""

    name = "fan_out"
    supported_entity_types = [EntityType.DOMAIN, EntityType.SUBDOMAIN]

    def __init__(self, fan: int = 2, delay: float = 0.0):
        self.fan, self.delay = fan, delay
        self.calls: list[str] = []

    async def run(self, entity, session, config):
        self.calls.append(entity.value)
        if self.delay:
            await asyncio.sleep(self.delay)
        for i in range(self.fan):
            c = child(entity, f"n{i}.{entity.value}", self.name)
            yield c
            yield Relation.create(source_id=entity.id, target_id=c.id, rel_type=RelationType.SUBDOMAIN_OF)


class EchoModule(FanOutModule):
    """Second module that rediscovers the same children (tests de-duplication)."""

    name = "echo"


class HangingModule(BaseModule):
    name = "hanging"
    supported_entity_types = [EntityType.DOMAIN]

    async def run(self, entity, session, config):
        await asyncio.sleep(60)
        yield entity  # pragma: no cover


class FailingModule(BaseModule):
    name = "failing"
    supported_entity_types = [EntityType.SUBDOMAIN]

    def __init__(self):
        self.calls = 0

    async def run(self, entity, session, config):
        self.calls += 1
        raise RuntimeError("upstream exploded")
        yield  # pragma: no cover


def make_engine(modules, **cfg) -> ArgusEngine:
    config = ScanConfig(target="example.com", target_type=EntityType.DOMAIN, **cfg)
    return ArgusEngine(config, bus=EventBus(), modules={m.name: m for m in modules})


async def test_recursion_respects_max_depth():
    mod = FanOutModule(fan=2)
    engine = make_engine([mod], max_depth=2)
    graph = await engine.start()
    # depth0: 1, depth1: 2, depth2: 4  -> depth-2 nodes are discovered but not expanded
    assert graph.node_count == 7
    assert graph.edge_count == 6
    assert len(mod.calls) == 3
    assert engine.investigation.status == InvestigationStatus.COMPLETED


async def test_duplicate_discoveries_are_merged():
    fan, echo = FanOutModule(fan=3), EchoModule(fan=3)
    engine = make_engine([fan, echo], max_depth=1)
    graph = await engine.start()
    assert graph.node_count == 4
    assert engine.module_stats["fan_out"].entities_found + engine.module_stats["echo"].entities_found == 3


async def test_entities_are_processed_in_parallel():
    mod = FanOutModule(fan=10, delay=0.3)
    engine = make_engine([mod], max_depth=1, concurrency_limit=10)
    t0 = time.monotonic()
    await engine.start()
    # seed (0.3s) + 10 children in parallel (0.3s). Sequential would be ~3.3s.
    assert time.monotonic() - t0 < 1.5
    assert len(mod.calls) == 1  # children at max depth are not expanded


async def test_module_timeout_does_not_stall_scan():
    engine = make_engine([HangingModule()], module_timeout_seconds=1)
    t0 = time.monotonic()
    await engine.start()
    assert time.monotonic() - t0 < 3
    stats = engine.module_stats["hanging"]
    assert stats.timed_out == 1 and stats.failed == 1
    assert engine.investigation.status == InvestigationStatus.COMPLETED


async def test_circuit_breaker_disables_flaky_module():
    failing = FailingModule()
    engine = make_engine(
        [FanOutModule(fan=6), failing],
        max_depth=2,
        concurrency_limit=1,
        circuit_breaker_threshold=2,
    )
    await engine.start()
    assert failing.calls == 2
    assert engine.module_stats["failing"].disabled is True
    assert any("Circuit breaker" in e for e in engine.investigation.errors)


async def test_entity_cap_truncates_graph():
    engine = make_engine([FanOutModule(fan=20)], max_depth=1, max_entities=5)
    graph = await engine.start()
    assert graph.node_count == 5
    assert engine.truncated is True


async def test_cancellation_stops_scan_quickly():
    engine = make_engine([FanOutModule(fan=3, delay=0.5)], max_depth=4)
    task = asyncio.create_task(engine.start())
    await asyncio.sleep(0.2)
    engine.cancel()
    t0 = time.monotonic()
    await task
    assert time.monotonic() - t0 < 0.5
    assert engine.investigation.status == InvestigationStatus.CANCELLED


async def test_lifecycle_events_and_stats_are_emitted():
    bus = EventBus()
    seen = []
    bus.subscribe_all(lambda e: seen.append(e))
    config = ScanConfig(target="example.com", target_type=EntityType.DOMAIN, max_depth=1)
    engine = ArgusEngine(config, bus=bus, modules={"fan_out": FanOutModule(fan=2)})
    await engine.start()

    types = [e.type for e in seen]
    assert types[0] == EventType.SCAN_STARTED and types[-1] == EventType.SCAN_COMPLETED
    assert types.count(EventType.ENTITY_DISCOVERED) == 2
    done = seen[-1].data
    assert done["module_stats"]["fan_out"]["succeeded"] == 1
    assert "analytics" in done and "duration_seconds" in done
