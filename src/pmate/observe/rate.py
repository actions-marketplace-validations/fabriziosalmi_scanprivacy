"""Per-host politeness.

The engine visits somebody else's server without asking first. The least it can
do is behave like one visitor rather than like a load test: at most one page
load per second per host, whatever the concurrency upstream.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict


class PerHostLimiter:
    """Guarantees at least `1/rps` seconds between two requests to one host."""

    def __init__(self, rps: float) -> None:
        if rps <= 0:
            raise ValueError("rps must be greater than zero")
        self._min_interval = 1.0 / rps
        self._last_at: dict[str, float] = defaultdict(float)
        self._lock = asyncio.Lock()

    async def wait(self, host: str) -> None:
        async with self._lock:
            now = time.monotonic()
            delay = self._last_at[host] + self._min_interval - now
            if delay > 0:
                await asyncio.sleep(delay)
            self._last_at[host] = time.monotonic()
