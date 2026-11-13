"""Base module abstraction for Argus OSINT collectors."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from typing import ClassVar

from argus.core.http import HttpClient
from argus.core.models import Entity, EntityType, Relation, ScanConfig
from argus.core.runctx import report_error as _report_error
from argus.core.runctx import report_ok as _report_ok
from argus.core.settings import get_settings
from argus.security.secrets import register_secret

logger = logging.getLogger("argus.module")


class BaseModule(ABC):
    """Abstract base class that all Argus reconnaissance modules implement."""

    name: str = "base_module"
    description: str = "Base reconnaissance module"
    supported_entity_types: ClassVar[list[EntityType]] = []
    # MITRE ATT&CK reconnaissance techniques this collector emulates (see argus/intel/attack.py).
    attack_techniques: ClassVar[tuple[str, ...]] = ()
    # True if the module connects to the *target's own* infrastructure (not just third-party
    # databases). Matters for engagements that only permit passive reconnaissance.
    active: ClassVar[bool] = False
    # Settings (attributes of argus.core.settings.Settings, e.g. "virustotal_api_key") that must be
    # set for the module to run. Modules with missing settings are not loaded.
    requires_settings: ClassVar[tuple[str, ...]] = ()
    # Minimum seconds between requests to specific hosts (third-party API quotas).
    rate_limits: ClassVar[dict[str, float]] = {}
    # "builtin", or "plugin:<package:object>" for third-party modules (see argus/modules/plugins.py).
    origin: ClassVar[str] = "builtin"

    @classmethod
    def is_configured(cls) -> bool:
        settings = get_settings()
        return all(_secret_value(getattr(settings, name, None)) for name in cls.requires_settings)

    def secret(self, name: str) -> str:
        """Read a secret setting and register it for redaction from all recorded errors."""
        value = _secret_value(getattr(get_settings(), name, None))
        register_secret(value)
        return value

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


def _secret_value(value: object) -> str:
    if value is None:
        return ""
    getter = getattr(value, "get_secret_value", None)
    return (getter() if getter else str(value)).strip()
