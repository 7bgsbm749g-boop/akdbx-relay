"""In-memory rate limits keyed by client IP.

Client IPs are kept only in memory, only as long as a limit needs them, and
are never written to disk or logs.

Each table has a size cap. When a new key arrives at a full table, the table
first drops entries that no longer limit anything, then the least recently
used entry. A flood of addresses can therefore reset other addresses' limits
early, but it can never lock every new address out.
"""

from __future__ import annotations

import time
from collections import deque
from typing import Callable


class TokenBucket:
    """Per-key token bucket: `rate` tokens per second, at most `burst` tokens."""

    def __init__(
        self,
        rate: float,
        burst: int,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 100_000,
    ) -> None:
        self.rate = rate
        self.burst = float(burst)
        self.clock = clock
        self.max_keys = max_keys
        self._buckets: dict[str, tuple[float, float]] = {}
        self._last_sweep = clock()

    def allow(self, key: str) -> bool:
        now = self.clock()
        self._sweep(now)
        entry = self._buckets.pop(key, None)  # re-inserted below: dict order is recency
        if entry is None and len(self._buckets) >= self.max_keys:
            self._sweep(now, force=True)
            while len(self._buckets) >= self.max_keys:
                del self._buckets[next(iter(self._buckets))]  # least recently used
        tokens, stamp = entry if entry is not None else (self.burst, now)
        tokens = min(self.burst, tokens + (now - stamp) * self.rate)
        if tokens < 1.0:
            self._buckets[key] = (tokens, now)
            return False
        self._buckets[key] = (tokens - 1.0, now)
        return True

    def refund(self, key: str) -> None:
        """Give back one token taken by allow()."""
        entry = self._buckets.get(key)
        if entry is not None:
            tokens, stamp = entry
            self._buckets[key] = (min(self.burst, tokens + 1.0), stamp)

    def _sweep(self, now: float, force: bool = False) -> None:
        if not force and now - self._last_sweep < 60:
            return
        self._last_sweep = now
        full_after = self.burst / self.rate
        stale = [k for k, (_, t) in self._buckets.items() if now - t > full_after]
        for k in stale:
            del self._buckets[k]

    def __len__(self) -> int:
        return len(self._buckets)


class SlidingWindow:
    """Per-key limit: at most `limit` events in the last `window` seconds."""

    def __init__(
        self,
        limit: int,
        window: float,
        clock: Callable[[], float] = time.monotonic,
        max_keys: int = 100_000,
    ) -> None:
        self.limit = limit
        self.window = window
        self.clock = clock
        self.max_keys = max_keys
        self._events: dict[str, deque[float]] = {}
        self._last_sweep = clock()

    def _trim(self, key: str, now: float) -> deque[float] | None:
        q = self._events.get(key)
        if q is None:
            return None
        while q and now - q[0] >= self.window:
            q.popleft()
        if not q:
            del self._events[key]
            return None
        return q

    def check(self, key: str) -> float:
        """Return 0 if an event is allowed now, else seconds until it is."""
        now = self.clock()
        self._sweep(now)
        q = self._trim(key, now)
        if q is None:
            return 0.0
        if len(q) < self.limit:
            return 0.0
        return max(1.0, self.window - (now - q[0]))

    def record(self, key: str) -> None:
        now = self.clock()
        q = self._events.pop(key, None)  # re-inserted below: dict order is recency
        if q is None:
            q = deque()
            if len(self._events) >= self.max_keys:
                self._sweep(now, force=True)
                while len(self._events) >= self.max_keys:
                    del self._events[next(iter(self._events))]  # least recently used
        q.append(now)
        self._events[key] = q

    def _sweep(self, now: float, force: bool = False) -> None:
        if not force and now - self._last_sweep < 60:
            return
        self._last_sweep = now
        for key in list(self._events):
            self._trim(key, now)

    def __len__(self) -> int:
        return len(self._events)
