from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import RateLimiterAdapter
from fastauth.protocols import RateLimitT


class SQLAlchemyRateLimiter(RateLimiterAdapter[RateLimitT]):
    """DB-backed fixed-window counter. Works across multiple processes/instances."""

    def __init__(self, db_session: AsyncSession, model: type[RateLimitT]):
        self.db_session = db_session
        self.model = model

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

        stmt = select(self.model).where(self.model.key == key).with_for_update()  # type: ignore[call-arg]
        result = await self.db_session.execute(stmt)
        row = result.scalar_one_or_none()

        if row is None:
            row = self.model(key=key, count=1, window_start=now)  # type: ignore[call-arg]
            self.db_session.add(row)
            await self.db_session.commit()
            return True

        window_start = row.window_start  # type: ignore[union-attr]
        if window_start.tzinfo is None:
            window_start = window_start.replace(tzinfo=UTC)

        if now - window_start > timedelta(seconds=window):
            row.count = 1  # type: ignore[union-attr]
            row.window_start = now  # type: ignore[union-attr]
            await self.db_session.commit()
            return True

        if row.count >= max_requests:  # type: ignore[union-attr]
            await self.db_session.commit()  # release the lock even on the blocked path
            return False

        row.count += 1  # type: ignore[union-attr]
        await self.db_session.commit()
        return True
