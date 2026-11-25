"""Rate limiting: sliding windows per API key, client address or account.

A limiter counts in memory by default. Once :func:`use_database` is called (the server does at start
up), limiters with a ``name`` count in the database instead, so the limit holds for the whole
deployment, not for each replica: three replicas no longer allow three times the sign-in attempts,
vault unlocks or Shodan-spending runs. Their async :meth:`SlidingWindowLimiter.allow` is what routes
call.

The shared count uses two fixed windows weighted by how far the current one has run (the usual
"sliding window counter"): the previous window's count times the share of it still inside the
sliding window, plus the current window's count. The attempt is added first (one upsert that returns
the new count) and taken back if it went over, so two replicas cannot both slip under the limit. If
the database cannot be reached, the limiter falls back to counting in memory for that attempt.

The per-request API budget stays in memory: it protects each replica's own capacity and runs on
every request, where a database round trip would cost more than it saves.
"""

from __future__ import annotations

import hashlib
import logging
import math
import random
import time
import weakref
from collections import defaultdict, deque
from typing import Any

logger = logging.getLogger("argus.ratelimit")
_ALL: weakref.WeakSet[SlidingWindowLimiter] = weakref.WeakSet()
_store: _DatabaseCounters | None = None


def reset_all() -> None:
    """Forget every limiter's history (tests start each case from a clean slate)."""
    for limiter in list(_ALL):
        limiter.reset()


def use_database(db: Any) -> None:
    """Count named limiters in ``db`` from now on (shared by every replica)."""
    global _store
    _store = _DatabaseCounters(db)


def use_memory() -> None:
    global _store
    _store = None


class SlidingWindowLimiter:
    """Allow at most ``limit`` events per ``window`` seconds for each key.

    ``name`` labels refusals in ``argus_rate_limited_total``; a named limiter is shared across
    replicas once :func:`use_database` has been called (``shared=False`` keeps it in memory).
    """

    def __init__(self, limit: int, window: float, name: str = "", shared: bool = True):
        self.name = name
        self.limit = limit
        self.window = window
        self.shared = shared and bool(name)
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._waits: dict[str, int] = {}  # the database's Retry-After for keys just refused
        _ALL.add(self)

    def reset(self) -> None:
        self._events.clear()
        self._waits.clear()

    async def allow(self, key: str) -> bool:
        """Record an attempt, deployment-wide when shared. False (and nothing recorded) if over the limit."""
        store = _store
        if store is None or not self.shared:
            return self.hit(key)
        try:
            wait = await store.hit(self.name, key, self.limit, self.window)
        except Exception:  # never let the counter's database lock everyone out, or let everyone in
            logger.warning("Shared rate limit %s unavailable; counting in memory", self.name, exc_info=True)
            return self.hit(key)
        if wait:
            self._waits[key] = wait
            if len(self._waits) > 10_000:
                self._waits.clear()
            return False
        self._waits.pop(key, None)
        return True

    def hit(self, key: str) -> bool:
        """Record an attempt in this process. Returns False (and records nothing) if over the limit."""
        now = time.monotonic()
        q = self._events[key]
        while q and now - q[0] >= self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True

    def retry_after(self, key: str) -> int:
        if key in self._waits:
            return self._waits[key]
        q = self._events.get(key)
        if not q:
            return 0
        return max(1, int(self.window - (time.monotonic() - q[0])) + 1)

    def remaining(self, key: str) -> int:
        now = time.monotonic()
        q = self._events.get(key)
        return self.limit - sum(1 for t in q if now - t < self.window) if q else self.limit


def estimate(previous: int, current: int, elapsed: float, window: float) -> float:
    """Events in the sliding window ending now: the share of the previous window still inside it, plus this one."""
    return previous * max(0.0, 1 - elapsed / window) + current


def wait_for(previous: int, current: int, elapsed: float, window: float, limit: int) -> int:
    """Seconds until one more event fits under ``limit`` (``current`` excludes the refused attempt)."""
    if current >= limit:  # wait for the next window, then for enough of this one to slide out
        later = window - elapsed + (window * (1 - limit / current) if current else 0)
    elif previous:
        later = window * (1 - (limit - current) / previous) - elapsed
    else:
        later = window - elapsed
    return max(1, min(int(2 * window), math.ceil(later)))


class _DatabaseCounters:
    def __init__(self, db: Any):
        self.db = db

    async def hit(self, name: str, key: str, limit: int, window: float) -> int:
        """Count an attempt; 0 when allowed, else the seconds to wait (the attempt is not counted)."""
        from sqlalchemy import Table, delete, select, update

        from argus.storage.db import RateLimitCounterRow

        table: Table = RateLimitCounterRow.__table__  # type: ignore[assignment]
        span = max(1, int(window))
        now = time.time()
        start = int(now // span * span)
        elapsed = now - start
        digest = hashlib.sha256(key.encode()).hexdigest()[:32]  # addresses and key ids are not stored
        if self.db.dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert  # type: ignore[assignment]
        where = (table.c.name == name, table.c.key == digest)
        async with self.db.session() as s, s.begin():
            upsert = insert(table).values(name=name, key=digest, window_start=start, count=1)
            added = upsert.on_conflict_do_update(index_elements=[table.c.name, table.c.key, table.c.window_start],
                                                 set_={"count": table.c.count + 1}).returning(table.c.count)  # fmt: skip
            current = int((await s.execute(added)).scalar_one())
            previous = int(
                await s.scalar(select(table.c.count).where(*where, table.c.window_start == start - span)) or 0
            )
            if estimate(previous, current, elapsed, span) > limit:
                await s.execute(update(table).where(*where, table.c.window_start == start)
                                .values(count=table.c.count - 1))  # fmt: skip
                return wait_for(previous, current - 1, elapsed, span, limit)
            if random.random() < 0.02:  # forget windows that no longer count
                await s.execute(delete(table).where(table.c.name == name, table.c.window_start < start - span))
        return 0
