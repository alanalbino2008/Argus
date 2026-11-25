"""Rate limiting: sliding windows per API key, client address or account.

A limiter counts in memory by default. Once :func:`use_database` is called (the server does at start
up), limiters with a ``name`` count in the database instead, so the limit holds for the whole
deployment, not for each replica: three replicas no longer allow three times the sign-in attempts,
vault unlocks or Shodan-spending runs. Their async :meth:`SlidingWindowLimiter.allow` is what routes
call.

The shared count is exact: attempts are counted in small buckets (a sixtieth of the window) and every
bucket inside the window is summed; a bucket the window's start falls inside counts in full, so the
limiter can only err on the strict side. (An earlier version weighted the previous fixed window by
how much of it remained, which undercounts bursts near a window boundary.) The attempt is added
first and taken back if it went over, so two replicas cannot both slip under the limit. If
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


def bucket_size(window: float) -> int:
    """Seconds per counting bucket: a sixtieth of the window (one second for a one-minute limit)."""
    return max(1, int(window // 60))


def in_window(buckets: list[tuple[int, int]], now: float, window: float) -> int:
    """Attempts in the window ending now. A bucket the window's start falls inside counts in full, so
    the count can only be slightly high (a little strict), never low (never lets more through)."""
    size = bucket_size(window)
    return sum(count for start, count in buckets if start + size > now - window)


def wait_for(buckets: list[tuple[int, int]], now: float, window: float, limit: int) -> int:
    """Seconds until one more attempt fits: until enough of the oldest buckets leave the window."""
    size = bucket_size(window)
    live = sorted((start, count) for start, count in buckets if start + size > now - window)
    total = sum(count for _, count in live)
    for start, count in live:
        if total < limit:
            break
        total -= count
        expires = start + size + window  # when this bucket stops counting
        if total < limit:
            return max(1, math.ceil(expires - now))
    return 1


class _DatabaseCounters:
    def __init__(self, db: Any):
        self.db = db

    async def hit(self, name: str, key: str, limit: int, window: float) -> int:
        """Count an attempt; 0 when allowed, else the seconds to wait (the attempt is not counted)."""
        from sqlalchemy import Table, delete, select, update

        from argus.storage.db import RateLimitCounterRow

        table: Table = RateLimitCounterRow.__table__  # type: ignore[assignment]
        size = bucket_size(window)
        now = time.time()
        start = int(now // size * size)
        digest = hashlib.sha256(key.encode()).hexdigest()[:32]  # addresses and key ids are not stored
        if self.db.dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert
        else:
            from sqlalchemy.dialects.sqlite import insert  # type: ignore[assignment]
        where = (table.c.name == name, table.c.key == digest)
        async with self.db.session() as s, s.begin():
            upsert = insert(table).values(name=name, key=digest, window_start=start, count=1)
            await s.execute(upsert.on_conflict_do_update(index_elements=[table.c.name, table.c.key, table.c.window_start],
                                                         set_={"count": table.c.count + 1}))  # fmt: skip
            rows = (await s.execute(select(table.c.window_start, table.c.count)
                                    .where(*where, table.c.window_start > now - window - size))).all()  # fmt: skip
            buckets = [(int(b), int(c)) for b, c in rows]
            if in_window(buckets, now, window) > limit:
                await s.execute(update(table).where(*where, table.c.window_start == start)
                                .values(count=table.c.count - 1))  # fmt: skip
                return wait_for([(b, c - 1 if b == start else c) for b, c in buckets], now, window, limit)
            if random.random() < 0.02:  # forget buckets that no longer count
                await s.execute(delete(table).where(table.c.name == name, table.c.window_start < now - window - size))
        return 0
