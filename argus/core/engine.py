"""Recursive OSINT Orchestration Engine for Argus.

Automates Spiderfoot-like multi-hop data enrichment, Sherlock-like rapid
handle hunting, and Maltego-like graph relationship synthesis.

Execution model
---------------
The seed entity is placed on an ``asyncio.Queue``. A pool of worker coroutines
pulls entities off the queue *in parallel*; for each entity every eligible
module runs concurrently. Newly discovered entities (within ``max_depth``) are
pushed back onto the queue. The scan finishes when the queue has been fully
drained (``Queue.join``), or when it is cancelled.

Robustness features
-------------------
* Per-module wall-clock timeouts - one slow data source cannot stall a scan.
* Circuit breaker - a module that fails repeatedly is disabled for the rest
  of the investigation instead of wasting time and requests.
* Entity cap (``max_entities``) - protects memory against graph explosions.
* Cooperative cancellation and explicit COMPLETED / CANCELLED / FAILED states.
* Per-module and HTTP telemetry recorded on the Investigation.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

import aiohttp

from argus.core.events import Event, EventBus, EventType, event_bus
from argus.core.graph import IntelligenceGraph
from argus.core.http import HttpClient
from argus.core.models import (
    Entity,
    Investigation,
    InvestigationStatus,
    Relation,
    ScanConfig,
)
from argus.core.runctx import ModuleRunReport, current_run
from argus.modules import get_default_modules
from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer
from argus.modules.base import BaseModule
from argus.security.network import GuardedResolver, configured_proxy_hosts
from argus.security.secrets import redact

logger = logging.getLogger("argus.engine")

MAX_WARNINGS = 500


@dataclass
class ModuleStats:
    """Execution telemetry for one module across an investigation."""

    runs: int = 0
    succeeded: int = 0
    degraded: int = 0
    failed: int = 0
    source_errors: int = 0
    timed_out: int = 0
    entities_found: int = 0
    relations_found: int = 0
    total_seconds: float = 0.0
    consecutive_failures: int = 0
    disabled: bool = False

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["total_seconds"] = round(self.total_seconds, 3)
        data["avg_seconds"] = round(self.total_seconds / self.runs, 3) if self.runs else 0.0
        return data


class ArgusEngine:
    """Core asynchronous recursive intelligence gathering orchestrator."""

    def __init__(
        self,
        config: ScanConfig,
        investigation_id: str | None = None,
        bus: EventBus | None = None,
        modules: dict[str, BaseModule] | None = None,
        session: aiohttp.ClientSession | None = None,
    ):
        self.investigation_id = investigation_id or f"inv_{uuid.uuid4().hex[:8]}"
        self.config = config
        self.bus = bus or event_bus
        self.graph = IntelligenceGraph(self.investigation_id)
        self.modules: dict[str, BaseModule] = modules if modules is not None else get_default_modules()

        if config.enabled_modules:
            self.modules = {name: mod for name, mod in self.modules.items() if name in config.enabled_modules}
        if config.passive_only:
            self.modules = {name: mod for name, mod in self.modules.items() if not mod.active}

        self.investigation = Investigation(
            id=self.investigation_id,
            name=f"Recon: {config.target} ({config.target_type.value})",
            config=config,
            status=InvestigationStatus.INITIALIZING,
        )

        self.module_stats: dict[str, ModuleStats] = {name: ModuleStats() for name in self.modules}
        self.http: HttpClient | None = None
        self.truncated = False

        self._external_session = session
        self._queue: asyncio.Queue[Entity] = asyncio.Queue()
        self._enqueued_ids: set[str] = set()
        self._processed_ids: set[str] = set()
        self._cancel_event = asyncio.Event()
        self._is_running = False

    # ------------------------------------------------------------------ public
    @property
    def is_running(self) -> bool:
        return self._is_running

    def cancel(self) -> None:
        """Request cooperative cancellation; ``start()`` returns with CANCELLED status."""
        self._cancel_event.set()

    async def start(self) -> IntelligenceGraph:
        """Execute the full recursive investigation and return the knowledge graph."""
        self._is_running = True
        self.investigation.status = InvestigationStatus.RUNNING
        started = time.monotonic()

        await self._emit(
            EventType.SCAN_STARTED,
            {
                "target": self.config.target,
                "target_type": self.config.target_type.value,
                "max_depth": self.config.max_depth,
                "active_modules": list(self.modules.keys()),
            },
        )

        seed = Entity.create(
            entity_type=self.config.target_type,
            value=self.config.target,
            label=self.config.target,
            source_module="seed",
            confidence=1.0,
            depth=0,
        )
        self.graph.add_entity(seed, is_seed=True)
        self._enqueue(seed)

        try:
            if self._external_session is not None:
                await self._run(self._external_session)
            else:
                resolver = (
                    None
                    if self.config.allow_private_targets
                    else GuardedResolver(trusted_hosts=configured_proxy_hosts())
                )
                connector = aiohttp.TCPConnector(
                    limit=100,
                    limit_per_host=self.config.per_host_concurrency,
                    ttl_dns_cache=300,
                    resolver=resolver,
                )
                # trust_env: honour HTTP(S)_PROXY / NO_PROXY, as required on corporate networks.
                async with aiohttp.ClientSession(connector=connector, trust_env=True) as session:
                    await self._run(session)
        except asyncio.CancelledError:
            # Externally cancelled (e.g. server shutdown): record it, then propagate.
            self._finalize(InvestigationStatus.CANCELLED, started)
            raise
        except Exception as exc:
            logger.exception("Investigation %s crashed", self.investigation_id)
            self.investigation.errors.append(f"Engine failure: {exc!r}")
            self._finalize(InvestigationStatus.FAILED, started)
            await self._emit(EventType.SCAN_FAILED, {"error": repr(exc), **self._summary(started)})
            raise

        if self._cancel_event.is_set():
            self._finalize(InvestigationStatus.CANCELLED, started)
            await self._emit(EventType.SCAN_CANCELLED, self._summary(started))
        else:
            self._finalize(InvestigationStatus.COMPLETED, started)
            await self._emit(
                EventType.SCAN_COMPLETED,
                {
                    **self._summary(started),
                    "analytics": self.investigation.analytics,
                },
            )
        return self.graph

    # ---------------------------------------------------------------- internals
    async def _run(self, session: aiohttp.ClientSession) -> None:
        self.http = HttpClient(
            session,
            max_retries=self.config.max_retries,
            min_host_interval=self.config.rate_limit_delay,
            per_host_concurrency=self.config.per_host_concurrency,
            global_concurrency=max(self.config.concurrency_limit * 4, 20),
            allow_private=self.config.allow_private_targets,
        )
        for module in self.modules.values():  # third-party API quotas (e.g. VirusTotal: 4/minute)
            for host, interval in module.rate_limits.items():
                self.http.limiter.set_host_interval(host, interval)
        workers = [
            asyncio.create_task(self._worker(i), name=f"argus-worker-{i}") for i in range(self.config.concurrency_limit)
        ]
        drained = asyncio.create_task(self._queue.join())
        cancelled = asyncio.create_task(self._cancel_event.wait())
        try:
            await asyncio.wait({drained, cancelled}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (*workers, drained, cancelled):
                task.cancel()
            await asyncio.gather(*workers, drained, cancelled, return_exceptions=True)

    async def _worker(self, worker_id: int) -> None:
        while True:
            entity = await self._queue.get()
            try:
                await self._process_entity(entity)
            except asyncio.CancelledError:
                raise
            except Exception:  # defensive: a bug here must never kill the pool
                logger.exception("Worker %d failed processing %s", worker_id, entity.id)
            finally:
                self._queue.task_done()

    async def _process_entity(self, entity: Entity) -> None:
        if entity.id in self._processed_ids:
            return
        self._processed_ids.add(entity.id)

        # The seed is always fully processed; the limit applies to what is discovered from it.
        at_limit = entity.depth > 0 and entity.depth >= self.config.max_depth
        eligible = [
            m
            for m in self.modules.values()
            if not self.module_stats[m.name].disabled
            and m.can_handle(entity)
            and (m.enrichment or not at_limit)  # at the depth limit only enrichers run
        ]
        if eligible:
            await asyncio.gather(*(self._execute_module(m, entity) for m in eligible))

        await self._emit(
            EventType.SCAN_PROGRESS,
            {
                "processed_nodes": len(self._processed_ids),
                "queued_nodes": self._queue.qsize(),
                "total_nodes": self.graph.node_count,
                "total_edges": self.graph.edge_count,
            },
        )

    async def _execute_module(self, module: BaseModule, entity: Entity) -> None:
        stats = self.module_stats[module.name]
        stats.runs += 1
        started = time.monotonic()
        report = ModuleRunReport(module=module.name, entity=entity.value)
        await self._emit(EventType.MODULE_STARTED, {"module": module.name, "entity": entity.label})

        try:
            await asyncio.wait_for(
                self._consume_module(module, entity, stats, report),
                timeout=self.config.module_timeout_seconds,
            )
        except asyncio.TimeoutError:
            stats.timed_out += 1
            await self._record_failure(module, entity, f"timed out after {self.config.module_timeout_seconds:.0f}s")
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - a buggy module must never crash the whole scan
            await self._record_failure(module, entity, repr(exc))
        else:
            await self._classify_run(module, entity, report)
        finally:
            stats.total_seconds += time.monotonic() - started
            stats.source_errors += report.source_errors

        await self._emit(
            EventType.MODULE_FINISHED,
            {
                "module": module.name,
                "entity": entity.label,
                "outcome": report.outcome,
                "source_errors": report.source_errors,
            },
        )

    async def _classify_run(self, module: BaseModule, entity: Entity, report: ModuleRunReport) -> None:
        """Turn a run that finished without raising into success / degraded / failed."""
        stats = self.module_stats[module.name]
        outcome = report.outcome
        if outcome == "failed":
            await self._record_failure(module, entity, "all data sources failed (" + "; ".join(report.errors[:3]) + ")")
            return
        stats.succeeded += 1
        stats.consecutive_failures = 0
        if outcome == "degraded":
            stats.degraded += 1
            msg = (
                f"Module {module.name} on {entity.value}: partial results, "
                f"{report.source_errors} source error(s) ({'; '.join(report.errors[:3])})"
            )
            self._add_warning(msg)
            await self._emit(EventType.LOG_MESSAGE, {"level": "WARNING", "message": msg})

    def _add_warning(self, msg: str) -> None:
        if len(self.investigation.warnings) < MAX_WARNINGS:
            self.investigation.warnings.append(msg)

    async def _consume_module(
        self, module: BaseModule, entity: Entity, stats: ModuleStats, report: ModuleRunReport
    ) -> None:
        current_run.set(report)  # visible to HttpClient and any tasks the module spawns
        async for item in module.run(entity, self.http, self.config):  # type: ignore[arg-type]
            if self._cancel_event.is_set():
                return
            report.items += 1
            if isinstance(item, Entity):
                await self._ingest_entity(item, module.name, stats)
            elif isinstance(item, Relation):
                if self.graph.get_entity(item.source_id) is None or self.graph.get_entity(item.target_id) is None:
                    continue  # endpoint dropped (e.g. entity cap reached)
                if self.graph.add_relation(item):
                    stats.relations_found += 1
                    await self._emit(
                        EventType.RELATION_DISCOVERED,
                        {
                            "relation": item.model_dump(mode="json"),
                            "source_module": module.name,
                        },
                    )

    async def _ingest_entity(self, item: Entity, module_name: str, stats: ModuleStats) -> None:
        if self.graph.get_entity(item.id) is None and self.graph.node_count >= self.config.max_entities:
            if not self.truncated:
                self.truncated = True
                msg = f"Entity cap of {self.config.max_entities} reached; further discoveries are dropped."
                self.investigation.errors.append(msg)
                await self._emit(EventType.LOG_MESSAGE, {"level": "WARNING", "message": msg})
            return

        if not self.graph.add_entity(item):
            return
        stats.entities_found += 1
        await self._emit(
            EventType.ENTITY_DISCOVERED,
            {
                "entity": item.model_dump(mode="json"),
                "source_module": module_name,
            },
        )
        if item.depth < self.config.max_depth:
            self._enqueue(item)
        elif item.depth == self.config.max_depth and any(
            m.enrichment and m.can_handle(item) for m in self.modules.values()
        ):
            # Leaf entities still get enriched (facts, lifecycle, CVE intel) - nothing they yield is expanded.
            self._enqueue(item)

    def _enqueue(self, entity: Entity) -> None:
        if entity.id not in self._enqueued_ids:
            self._enqueued_ids.add(entity.id)
            self._queue.put_nowait(entity)

    async def _record_failure(self, module: BaseModule, entity: Entity, reason: str) -> None:
        stats = self.module_stats[module.name]
        stats.failed += 1
        stats.consecutive_failures += 1
        msg = redact(f"Module {module.name} failed on {entity.value}: {reason}")
        logger.warning(msg)
        self.investigation.errors.append(msg)
        await self._emit(EventType.LOG_MESSAGE, {"level": "ERROR", "message": msg})
        if not stats.disabled and stats.consecutive_failures >= self.config.circuit_breaker_threshold:
            stats.disabled = True
            notice = (
                f"Circuit breaker opened: {module.name} disabled after "
                f"{stats.consecutive_failures} consecutive failures."
            )
            self.investigation.errors.append(notice)
            await self._emit(EventType.LOG_MESSAGE, {"level": "WARNING", "message": notice})

    def _summary(self, started: float) -> dict[str, Any]:
        return {
            "node_count": self.graph.node_count,
            "edge_count": self.graph.edge_count,
            "duration_seconds": round(time.monotonic() - started, 3),
            "truncated": self.truncated,
            "module_stats": self.investigation.module_stats,
            "http_stats": self.investigation.http_stats,
        }

    def _finalize(self, status: InvestigationStatus, started: float) -> None:
        self._is_running = False
        inv = self.investigation
        inv.status = status
        inv.completed_at = datetime.now(timezone.utc)
        inv.node_count = self.graph.node_count
        inv.edge_count = self.graph.edge_count
        inv.module_stats = {name: s.as_dict() for name, s in self.module_stats.items()}
        inv.http_stats = self.http.stats.as_dict() if self.http else {}
        inv.truncated = self.truncated
        try:  # partial graphs from cancelled/failed scans are still worth scoring
            inv.analytics = GraphIntelligenceAnalyzer.analyze(self.graph)
        except Exception:
            logger.exception("Graph analytics failed for %s", self.investigation_id)

    async def _emit(self, event_type: EventType, data: dict[str, Any]) -> None:
        await self.bus.emit(Event(type=event_type, investigation_id=self.investigation_id, data=data))
