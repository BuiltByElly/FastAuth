# fastauth/rate_limit/memory.py
"""Single-process only — do not use across multiple workers/instances."""

from datetime import UTC, datetime, timedelta

from fastauth.adapters.adapters import RateLimiterAdapter


class InMemoryRateLimiter(RateLimiterAdapter):
    """Check if the given key has exceeded the rate limit within the given window.
    Stores state in memory only, so does not persist across worker restarts.
    Args:
        key: A primary key string, typically f"{ip}:{request.url.path}"
        window: The time window in seconds
        max_requests: The maximum number of requests allowed within the window
    Returns:
        True if the key has not exceeded the rate limit, False otherwise.
    """

    def __init__(self):
        self._store: dict[str, tuple[int, datetime]] = {}

    async def check(self, key: str, window: int, max_requests: int) -> bool:
        now = datetime.now(UTC)
        entry = self._store.get(key)

        if entry is None or now - entry[1] > timedelta(seconds=window):
            self._store[key] = (1, now)
            return True

        count, window_start = entry
        if count >= max_requests:
            return False

        self._store[key] = (count + 1, window_start)
        return True
