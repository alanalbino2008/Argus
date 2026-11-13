"""In-memory sliding-window rate limiter (per API key / per client IP)."""

from __future__ import annotations

from collections import defaultdict, deque
import time
from typing import Deque, Dict


class SlidingWindowLimiter:
    """Allow at most ``limit`` events per ``window`` seconds for each key.

    Single-process only; a multi-replica deployment would back this with Redis.
    """

    def __init__(self, limit: int, window: float):
        self.limit = limit
        self.window = window
        self._events: Dict[str, Deque[float]] = defaultdict(deque)

    def hit(self, key: str) -> bool:
        """Record an attempt. Returns False (and records nothing) if over the limit."""
        now = time.monotonic()
        q = self._events[key]
        while q and now - q[0] >= self.window:
            q.popleft()
        if len(q) >= self.limit:
            return False
        q.append(now)
        return True

    def retry_after(self, key: str) -> int:
        q = self._events.get(key)
        if not q:
            return 0
        return max(1, int(self.window - (time.monotonic() - q[0])) + 1)
