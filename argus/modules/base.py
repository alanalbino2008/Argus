"""Base module abstraction for Argus OSINT collectors."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, ScanConfig
from argus.core.runctx import report_error as _report_error
from argus.core.runctx import report_ok as _report_ok

logger = logging.getLogger("argus.module")


class BaseModule(ABC):
    """Abstract base class that all Argus reconnaissance modules implement."""

    name: str = "base_module"
    description: str = "Base reconnaissance module"
    supported_entity_types: list[EntityType] = []

    def report_error(self, source: str, error: object) -> None:
        """Record that a data source failed during this run (e.g. a DNS timeout).

        Use it inside ``except`` blocks that deliberately swallow an error so the
        module can carry on with other sources. HTTP failures through the shared
        client are recorded automatically.
        """
        _report_error(source, error)

    def report_ok(self) -> None:
        """Record that a non-HTTP data source (DNS, raw socket...) answered."""
        _report_ok()

    def can_handle(self, entity: Entity) -> bool:
        """Determine if this module can process the given entity type."""
        return entity.type in self.supported_entity_types

    @abstractmethod
    async def run(
        self,
        entity: Entity,
        session: HttpClient,
        config: ScanConfig,
    ) -> AsyncIterator[Entity | Relation]:
        """Execute intelligence gathering on target entity.

        ``session`` is the shared resilient :class:`HttpClient` (aiohttp-compatible
        ``get``/``head``/``post``), which already handles retries and rate limits.
        Yields newly discovered Entity and Relation instances.
        """
        yield  # type: ignore
