"""Recursive OSINT Orchestration Engine for Argus.

Automates Spiderfoot-like multi-hop data enrichment, Sherlock-like rapid
credential/handle hunting, and Maltego-like graph relationship synthesis.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
import uuid
from typing import Dict, List, Optional, Set
import aiohttp

from argus.core.events import Event, EventBus, EventType, event_bus
from argus.core.graph import IntelligenceGraph
from argus.core.models import (
    Entity,
    EntityType,
    Investigation,
    InvestigationStatus,
    Relation,
    ScanConfig,
)
from argus.modules import get_default_modules
from argus.modules.analytics.graph_analyzer import GraphIntelligenceAnalyzer
from argus.modules.base import BaseModule

logger = logging.getLogger("argus.engine")


class ArgusEngine:
    """Core asynchronous recursive intelligence gathering orchestrator."""

    def __init__(
        self,
        config: ScanConfig,
        investigation_id: Optional[str] = None,
        bus: Optional[EventBus] = None,
    ):
        self.investigation_id = investigation_id or f"inv_{uuid.uuid4().hex[:8]}"
        self.config = config
        self.bus = bus or event_bus
        self.graph = IntelligenceGraph(self.investigation_id)
        self.modules: Dict[str, BaseModule] = get_default_modules()

        # Filter modules if specific subset was requested
        if config.enabled_modules:
            self.modules = {
                name: mod for name, mod in self.modules.items()
                if name in config.enabled_modules
            }

        self.investigation = Investigation(
            id=self.investigation_id,
            name=f"Recon: {config.target} ({config.target_type.value})",
            config=config,
            status=InvestigationStatus.INITIALIZING,
        )

        self._queue: asyncio.Queue[Entity] = asyncio.Queue()
        self._enqueued_ids: Set[str] = set()
        self._processed_ids: Set[str] = set()
        self._session: Optional[aiohttp.ClientSession] = None
        self._is_running = False

    async def start(self) -> IntelligenceGraph:
        """Execute full recursive intelligence investigation."""
        self._is_running = True
        self.investigation.status = InvestigationStatus.RUNNING

        await self.bus.emit(Event(
            type=EventType.SCAN_STARTED,
            investigation_id=self.investigation_id,
            data={
                "target": self.config.target,
                "target_type": self.config.target_type.value,
                "max_depth": self.config.max_depth,
                "active_modules": list(self.modules.keys()),
            },
        ))

        # Seed entity creation
        seed_entity = Entity.create(
            entity_type=self.config.target_type,
            value=self.config.target,
            label=self.config.target,
            source_module="seed",
            confidence=1.0,
            depth=0,
        )
        self.graph.add_entity(seed_entity, is_seed=True)
        self._queue.put_nowait(seed_entity)
        self._enqueued_ids.add(seed_entity.id)

        # HTTP Session initialization
        connector = aiohttp.TCPConnector(limit=50, ttl_dns_cache=300)
        async with aiohttp.ClientSession(connector=connector) as session:
            self._session = session
            await self._run_enrichment_loop()

        self._is_running = False
        self.investigation.status = InvestigationStatus.COMPLETED
        self.investigation.completed_at = datetime.now(timezone.utc)
        self.investigation.node_count = self.graph.node_count
        self.investigation.edge_count = self.graph.edge_count

        # Run final graph analytics
        analytics = GraphIntelligenceAnalyzer.analyze(self.graph)

        await self.bus.emit(Event(
            type=EventType.SCAN_COMPLETED,
            investigation_id=self.investigation_id,
            data={
                "node_count": self.graph.node_count,
                "edge_count": self.graph.edge_count,
                "analytics": analytics,
            },
        ))

        return self.graph

    async def _run_enrichment_loop(self):
        """Processes queued entities up to max_depth."""
        while not self._queue.empty() and self._is_running:
            entity = await self._queue.get()
            if entity.id in self._processed_ids:
                self._queue.task_done()
                continue

            self._processed_ids.add(entity.id)

            # Discover eligible modules
            matching_modules = [m for m in self.modules.values() if m.can_handle(entity)]
            if not matching_modules:
                self._queue.task_done()
                continue

            # Run all eligible modules on this entity concurrently
            tasks = [self._execute_module(mod, entity) for mod in matching_modules]
            await asyncio.gather(*tasks, return_exceptions=True)

            self._queue.task_done()

            # Broadcast progress
            await self.bus.emit(Event(
                type=EventType.SCAN_PROGRESS,
                investigation_id=self.investigation_id,
                data={
                    "processed_nodes": len(self._processed_ids),
                    "queued_nodes": self._queue.qsize(),
                    "total_nodes": self.graph.node_count,
                    "total_edges": self.graph.edge_count,
                },
            ))

    async def _execute_module(self, module: BaseModule, entity: Entity):
        """Safely executes a single reconnaissance module against an entity."""
        if not self._session:
            return

        try:
            await self.bus.emit(Event(
                type=EventType.MODULE_STARTED,
                investigation_id=self.investigation_id,
                data={"module": module.name, "entity": entity.label},
            ))

            async for item in module.run(entity, self._session, self.config):
                if isinstance(item, Entity):
                    is_new = self.graph.add_entity(item)
                    if is_new:
                        await self.bus.emit(Event(
                            type=EventType.ENTITY_DISCOVERED,
                            investigation_id=self.investigation_id,
                            data={
                                "entity": item.model_dump(mode="json"),
                                "source_module": module.name,
                            },
                        ))

                        # Queue for recursive enrichment if within depth limits
                        if item.depth < self.config.max_depth and item.id not in self._enqueued_ids:
                            self._enqueued_ids.add(item.id)
                            self._queue.put_nowait(item)

                elif isinstance(item, Relation):
                    is_new = self.graph.add_relation(item)
                    if is_new:
                        await self.bus.emit(Event(
                            type=EventType.RELATION_DISCOVERED,
                            investigation_id=self.investigation_id,
                            data={
                                "relation": item.model_dump(mode="json"),
                                "source_module": module.name,
                            },
                        ))

            await self.bus.emit(Event(
                type=EventType.MODULE_FINISHED,
                investigation_id=self.investigation_id,
                data={"module": module.name, "entity": entity.label},
            ))

        except asyncio.CancelledError:
            raise
        except Exception as e:
            err_msg = f"Module {module.name} failed on {entity.value}: {e}"
            logger.error(err_msg)
            self.investigation.errors.append(err_msg)
            await self.bus.emit(Event(
                type=EventType.LOG_MESSAGE,
                investigation_id=self.investigation_id,
                data={"level": "ERROR", "message": err_msg},
            ))
