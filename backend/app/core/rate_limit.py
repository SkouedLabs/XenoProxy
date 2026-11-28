"""Fixed-window rate limiting shared by the middleware and the routes that report on it.

The counters live in this process. A deployment that runs several API workers
gets one window per worker, which is the existing trade-off of this limiter.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

# Anonymous submissions: each one spends the instance's API quotas.
PUBLIC_SUBMISSION_PATH = "/api/v1/public/submissions"
PUBLIC_SUBMISSION_LIMIT = 10
PUBLIC_SUBMISSION_WINDOW = 3600


class FixedWindowLimiter:
    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque[float]] = defaultdict(deque)

    def _window(self, key: tuple[str, str], window: int, now: float) -> deque[float]:
        bucket = self._hits[key]
        while bucket and now - bucket[0] > window:
            bucket.popleft()
        return bucket

    def consume(self, key: tuple[str, str], limit: int, window: int) -> float | None:
        """Count one hit. Returns None when allowed, otherwise the seconds to wait."""
        now = time.monotonic()
        bucket = self._window(key, window, now)
        if len(bucket) >= limit:
            return max(0.0, window - (now - bucket[0]))
        bucket.append(now)
        return None

    def peek(self, key: tuple[str, str], limit: int, window: int) -> tuple[int, int]:
        """Hits left in the window, and seconds until the oldest one expires."""
        now = time.monotonic()
        bucket = self._window(key, window, now)
        remaining = max(0, limit - len(bucket))
        reset = 0 if not bucket else max(0, int(window - (now - bucket[0])) + 1)
        return remaining, reset


limiter = FixedWindowLimiter()
