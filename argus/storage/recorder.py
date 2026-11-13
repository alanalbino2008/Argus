"""Write-behind persistence for a running investigation.

Writing every discovered entity to the database the instant it appears would
put disk I/O on the engine's hot path. Instead the recorder:

1. listens to the event bus and buffers new entities/relations in memory,
2. flushes the buffer in one batched transaction every ``flush_interval``
   seconds (so a crash loses at most ~1 second of findings), and
3. writes a full, authoritative snapshot when the scan ends.

A database hiccup is logged and retried on the next flush - it never fails the
scan itself.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

from argus.core.engine import ArgusEngine
from argus.core.events import Event, EventType
from argus.storage.repository import InvestigationRepository

logger = logging.getLogger("argus.storage.recorder")


class InvestigationRecorder:
    def __init__(self, repo: InvestigationRepository, engine: ArgusEngine, flush_interval: float = 1.0):
        self.repo = repo
        self.engine = engine
        self.flush_interval = flush_interval
        self._entities: Dict[str, Dict[str, Any]] = {}
        self._relations: Dict[str, Dict[str, Any]] = {}
        self._task: Optional[asyncio.Task[None]] = None
        self._lock = asyncio.Lock()
        self.flushes = 0

    async def start(self) -> None:
        await self.repo.save_investigation(self.engine.investigation)
        self.engine.bus.subscribe_all(self._on_event)
        self._task = asyncio.create_task(self._flush_loop(), name=f"recorder-{self.engine.investigation_id}")

    async def finish(self) -> None:
        """Stop periodic flushing and persist the final, complete state."""
        self.engine.bus.unsubscribe_all(self._on_event)
        if self._task:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)
        async with self._lock:
            self._entities.clear()
            self._relations.clear()
            await self.repo.save_graph(self.engine.graph)
            await self.repo.save_investigation(self.engine.investigation)
            self.flushes += 1

    async def _on_event(self, event: Event) -> None:
        if event.investigation_id != self.engine.investigation_id:
            return
        if event.type == EventType.ENTITY_DISCOVERED:
            ent = event.data["entity"]
            self._entities[ent["id"]] = ent
        elif event.type == EventType.RELATION_DISCOVERED:
            rel = event.data["relation"]
            self._relations[rel["id"]] = rel

    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(self.flush_interval)
            try:
                await self.flush()
            except asyncio.CancelledError:
                raise
            except Exception:
                logger.exception("Checkpoint failed for %s; will retry", self.engine.investigation_id)

    async def flush(self) -> None:
        async with self._lock:
            if not self._entities and not self._relations:
                return
            entities, self._entities = self._entities, {}
            relations, self._relations = self._relations, {}
            try:
                # Entities first: relations reference them.
                await self.repo.upsert_entities(self.engine.investigation_id, entities.values())
                await self.repo.upsert_relations(self.engine.investigation_id, relations.values())
                inv = self.engine.investigation
                inv.node_count, inv.edge_count = self.engine.graph.node_count, self.engine.graph.edge_count
                await self.repo.save_investigation(inv)
                self.flushes += 1
            except Exception:
                # Put the batch back so nothing is lost; newer copies win.
                self._entities = {**entities, **self._entities}
                self._relations = {**relations, **self._relations}
                raise
