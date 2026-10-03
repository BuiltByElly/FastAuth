import redis.asyncio as redis

from fastauth.adapters import RateLimiterAdapter


class RedisRateLimiterAdapter(RateLimiterAdapter):
    """Fixed-window rate limiting backed by Redis.

    Atomic via a Lua script (INCR + conditional EXPIRE in one round
    trip) so concurrent requests can't race past the limit.
    """

    _SCRIPT = """
        local current = redis.call("INCR", KEYS[1])
        if current == 1 then
            redis.call("EXPIRE", KEYS[1], ARGV[2])
        end
        if current > tonumber(ARGV[1]) then
            return 0
        end
        return 1
    """

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.script = redis_client.register_script(self._SCRIPT)

    async def check(self, key: str, window: int, max_requests: int) -> bool:
        """True if allowed (and increments count), False if over limit."""
        result = await self.script(keys=[key], args=[max_requests, window])
        return bool(result)
