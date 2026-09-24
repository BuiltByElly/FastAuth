from datetime import UTC, datetime, timedelta

from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import RateLimiterAdapter
from fastauth.protocols import RateLimitT


class SQLAlchemyRateLimiter(RateLimiterAdapter[RateLimitT]):
    """DB-backed fixed-window counter. Works across multiple processes/instances."""

    def __init__(self, db_session: AsyncSession, model: type[RateLimitT]):
        super().__init__(
            db_session,
            model,
        )

    async def check(self, key: str, window: int, max_requests: int) -> bool:
        """Check if the given key has exceeded the rate limit within the given window.
        Stores state in the database, so persists across worker restarts.
        Commits immediately: the check runs as a route dependency, before the
        endpoint, so a later endpoint failure (e.g. 401) must not roll back
        the attempt count.
        Args:
            key: A primary key string, typically f"{ip}:{request.url.path}"
            window: The time window in seconds
            max_requests: The maximum number of requests allowed within the window
        Returns:
            True if the key has not exceeded the rate limit, False otherwise
        """
        now = datetime.now(UTC)
        row = await self.db_session.get(self.model, key)

        if row is None:
            # first request ever for this key
            row = self.model(key=key, count=1, window_start=now)  # type: ignore[call-arg]
            self.db_session.add(row)
            await self.db_session.commit()
            return True

        window_start = row.window_start
        if window_start.tzinfo is None:
            window_start = window_start.replace(tzinfo=UTC)

        if now - window_start > timedelta(seconds=window):
            # window expired, reset
            row.count = 1
            row.window_start = now
            await self.db_session.commit()
            return True

        if row.count >= max_requests:
            return False  # over limit, don't increment further

        row.count += 1
        await self.db_session.commit()
        return True
