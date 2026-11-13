"""Base module abstraction for Argus OSINT collectors."""

from __future__ import annotations

from abc import ABC, abstractmethod
import logging
from typing import AsyncIterator, List, Union
from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, ScanConfig

logger = logging.getLogger("argus.module")


class BaseModule(ABC):
    """Abstract base class that all Argus reconnaissance modules implement."""

    name: str = "base_module"
    description: str = "Base reconnaissance module"
    supported_entity_types: List[EntityType] = []

    def can_handle(self, entity: Entity) -> bool:
        """Determine if this module can process the given entity type."""
        return entity.type in self.supported_entity_types

    @abstractmethod
    async def run(
        self,
        entity: Entity,
        session: HttpClient,
        config: ScanConfig,
    ) -> AsyncIterator[Union[Entity, Relation]]:
        """Execute intelligence gathering on target entity.

        ``session`` is the shared resilient :class:`HttpClient` (aiohttp-compatible
        ``get``/``head``/``post``), which already handles retries and rate limits.
        Yields newly discovered Entity and Relation instances.
        """
        yield  # type: ignore
