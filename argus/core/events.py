"""Asynchronous Event Bus for real-time telemetry and WebSocket streaming."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from enum import Enum
import logging
from typing import Any, Callable, Coroutine, Dict, List, Set
from pydantic import BaseModel, Field

logger = logging.getLogger("argus.events")


class EventType(str, Enum):
    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    ENTITY_DISCOVERED = "entity_discovered"
    RELATION_DISCOVERED = "relation_discovered"
    MODULE_STARTED = "module_started"
    MODULE_FINISHED = "module_finished"
    LOG_MESSAGE = "log_message"


class Event(BaseModel):
    """Event payload emitted by the engine and modules."""
    type: EventType
    investigation_id: str
    data: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


Subscriber = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus:
    """Central event broker for Argus. Dispatches events to subscribers and WebSocket connections."""

    def __init__(self):
        self._subscribers: Dict[EventType, Set[Subscriber]] = {t: set() for t in EventType}
        self._global_subscribers: Set[Subscriber] = set()

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

        tasks = []
        for cb in callbacks:
            tasks.append(self._safe_invoke(cb, event))

        await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_invoke(self, callback: Subscriber, event: Event):
        try:
            import inspect
            if inspect.iscoroutinefunction(callback):
                await callback(event)
            else:
                res = callback(event)
                if inspect.isawaitable(res):
                    await res
        except Exception as e:
            logger.error("Error executing subscriber callback for %s: %s", event.type, e)


# Global singleton instance for app-wide event distribution
event_bus = EventBus()
