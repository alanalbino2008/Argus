"""Asynchronous Event Bus for real-time telemetry and WebSocket streaming."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Coroutine
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("argus.events")


class EventType(str, Enum):
    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_CANCELLED = "scan_cancelled"
    ENTITY_DISCOVERED = "entity_discovered"
    RELATION_DISCOVERED = "relation_discovered"
    MODULE_STARTED = "module_started"
    MODULE_FINISHED = "module_finished"
    LOG_MESSAGE = "log_message"


class Event(BaseModel):
    """Event payload emitted by the engine and modules."""

    type: EventType
    investigation_id: str
    data: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


Subscriber = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus:
    """Central event broker for Argus. Dispatches events to subscribers and WebSocket connections."""

    def __init__(self):
        self._subscribers: dict[EventType, set[Subscriber]] = {t: set() for t in EventType}
        self._global_subscribers: set[Subscriber] = set()

    def subscribe(self, event_type: EventType, callback: Subscriber):
        """Register a callback for a specific event type."""
        self._subscribers[event_type].add(callback)

    def subscribe_all(self, callback: Subscriber):
        """Register a callback for all events."""
        self._global_subscribers.add(callback)

    def unsubscribe(self, event_type: EventType, callback: Subscriber):
        self._subscribers[event_type].discard(callback)

    def unsubscribe_all(self, callback: Subscriber):
        self._global_subscribers.discard(callback)
        for sub_set in self._subscribers.values():
            sub_set.discard(callback)

    async def emit(self, event: Event):
        """Publish an event to all interested subscribers concurrently."""
        callbacks = list(self._subscribers.get(event.type, set())) + list(self._global_subscribers)
        if not callbacks:
            return

        await asyncio.gather(*(self._safe_invoke(cb, event) for cb in callbacks), return_exceptions=True)

    async def _safe_invoke(self, callback: Subscriber, event: Event):
        try:
            import inspect

            if inspect.iscoroutinefunction(callback):
                await callback(event)
            else:
                res = callback(event)
                if inspect.isawaitable(res):
                    await res
        except Exception:
            logger.exception("Error executing subscriber callback for %s", event.type)


# Global singleton instance for app-wide event distribution
event_bus = EventBus()
