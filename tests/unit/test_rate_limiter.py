"""Unit tests: limiter backends, wiring validation, and dependency behavior."""

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
import redis.asyncio as redis
from fastapi import HTTPException, Request

from fastauth.adapters.rate_limit.memory import InMemoryRateLimiter
from fastauth.adapters.rate_limit.redis import RedisRateLimiterAdapter
from fastauth.adapters.rate_limit.sqlalchemy import SQLAlchemyRateLimiter
from fastauth.config import RateLimitConfig
from fastauth.dependencies.rate_limiter import RateLimiter, _client_ip
from tests.conftest import RateLimitRow


def make_request(path="/login", headers=None, client_host="1.2.3.4"):
    """Minimal Starlette request for direct dependency calls."""
    scope = {
        "type": "http",
        "method": "POST",
        "path": path,
        "headers": [
            (k.lower().encode(), v.encode()) for k, v in (headers or {}).items()
        ],
        "query_string": b"",
        "server": ("testserver", 80),
        "scheme": "http",
        "client": (client_host, 1234) if client_host else None,
    }
    return Request(scope)


async def test_memory_allows_then_denies_within_window():
    limiter = InMemoryRateLimiter()
    assert await limiter.check("k", window=60, max_requests=2) is True
    assert await limiter.check("k", window=60, max_requests=2) is True
    assert await limiter.check("k", window=60, max_requests=2) is False
    # Independent keys are unaffected.
    assert await limiter.check("other", window=60, max_requests=2) is True


async def test_memory_window_reset_reallows():
    limiter = InMemoryRateLimiter()
    assert await limiter.check("k", window=0, max_requests=1) is True
    # window=0 expires immediately, so the next call resets the counter.
    assert await limiter.check("k", window=0, max_requests=1) is True


async def test_limit_for_uses_custom_rule_then_raises_429():
    limiter = RateLimiter(
        rate_limit_config=RateLimitConfig(custom_rules={"/login": (60, 1)})
    )
    dep = limiter.limit_for("/login")
    assert (
        await dep(make_request("/login"), limiter=await limiter._dependency()) is None
    )
    with pytest.raises(HTTPException) as exc:
        await dep(make_request("/login"), limiter=await limiter._dependency())
    assert exc.value.status_code == 429


async def test_limit_for_falls_back_to_globals():
    limiter = RateLimiter(
        rate_limit_config=RateLimitConfig(window=60, max_requests=1, custom_rules={})
    )
    dep = limiter.limit_for("/unlisted")
    await dep(make_request("/unlisted"), limiter=await limiter._dependency())
    with pytest.raises(HTTPException) as exc:
        await dep(make_request("/unlisted"), limiter=await limiter._dependency())
    assert exc.value.status_code == 429


async def test_limit_explicit_args_override_config():
    limiter = RateLimiter(
        rate_limit_config=RateLimitConfig(window=60, max_requests=100)
    )
    dep = limiter.limit(window=60, max_requests=1)
    await dep(make_request(), limiter=await limiter._dependency())
    with pytest.raises(HTTPException):
        await dep(make_request(), limiter=await limiter._dependency())


def test_disabled_limiter_never_touches_storage():
    limiter = RateLimiter(
        rate_limit_config=RateLimitConfig(enabled=False, storage="database")
    )
    # No model/adapter/dependency needed when disabled.
    assert limiter._dependency is None


async def test_disabled_dependencies_are_noops():
    limiter = RateLimiter(rate_limit_config=RateLimitConfig(enabled=False))
    assert await limiter.limit_for("/login")(make_request()) is None
    assert await limiter.limit(window=1, max_requests=1)(make_request()) is None


def test_database_storage_requires_model_and_adapter():
    cfg = RateLimitConfig(storage="database")
    with pytest.raises(ValueError, match="rate_limit_model"):
        RateLimiter(rate_limit_config=cfg)
    with pytest.raises(ValueError, match="db_session_dependency"):
        RateLimiter(rate_limit_model=object, rate_limit_config=cfg)
    with pytest.raises(ValueError, match="rate_limiter_adapter"):
        RateLimiter(
            rate_limit_model=object,
            db_session_dependency=lambda: None,
            rate_limit_config=cfg,
        )


def test_client_ip_prefers_opt_in_header():
    req = make_request(headers={"x-forwarded-for": "9.9.9.9, 1.1.1.1"})
    assert _client_ip(req, "x-forwarded-for") == "9.9.9.9"
    # Without opt-in the header is ignored (spoof-proof default).
    assert _client_ip(req, None) == "1.2.3.4"
    assert _client_ip(make_request(client_host=None), None) == "unknown"


# --- redis backend -----------------------------------------------------------


@pytest.fixture
async def redis_client():
    """Real redis on an isolated DB; skipped when no server is reachable."""
    client = redis.Redis(host="localhost", port=6379, db=15)
    try:
        await client.ping()
    except Exception:
        await client.aclose()
        pytest.skip("redis-server not available at localhost:6379")
    await client.flushdb()
    yield client
    await client.flushdb()
    await client.aclose()


def _redis_key():
    return f"test:{uuid.uuid4().hex}"


async def test_redis_allows_then_denies_within_window(redis_client):
    limiter = RedisRateLimiterAdapter(redis_client)
    key = _redis_key()
    assert await limiter.check(key, window=60, max_requests=2) is True
    assert await limiter.check(key, window=60, max_requests=2) is True
    assert await limiter.check(key, window=60, max_requests=2) is False
    # Independent keys are unaffected.
    assert await limiter.check(_redis_key(), window=60, max_requests=2) is True


async def test_redis_sets_expiry_on_first_hit(redis_client):
    """The Lua script's conditional EXPIRE bounds the window server-side."""
    limiter = RedisRateLimiterAdapter(redis_client)
    key = _redis_key()
    assert await limiter.check(key, window=60, max_requests=5) is True
    ttl = await redis_client.ttl(key)
    assert 0 < ttl <= 60


def test_redis_storage_requires_client_and_adapter():
    cfg = RateLimitConfig(storage="redis")
    with pytest.raises(ValueError, match="redis_client"):
        RateLimiter(rate_limit_config=cfg)
    # An unconnected client never touches the network — no server needed.
    with pytest.raises(ValueError, match="rate_limiter_adapter"):
        RateLimiter(
            redis_client=redis.Redis(host="localhost", port=6379, db=15),
            rate_limit_config=cfg,
        )


async def test_redis_limiter_enforces_via_dependency(redis_client):
    limiter = RateLimiter(
        rate_limiter_adapter=RedisRateLimiterAdapter,
        redis_client=redis_client,
        rate_limit_config=RateLimitConfig(storage="redis"),
    )
    dep = limiter.limit(window=60, max_requests=1)
    # Unique path per test — the shared server has no other state for it.
    path = f"/redis-{uuid.uuid4().hex}"
    await dep(make_request(path), limiter=await limiter._dependency())
    with pytest.raises(HTTPException) as exc:
        await dep(make_request(path), limiter=await limiter._dependency())
    assert exc.value.status_code == 429


# --- sqlalchemy row-locking --------------------------------------------------


async def test_sqlalchemy_blocked_path_commits_and_denies():
    """Over-limit hits still commit, releasing the FOR UPDATE row lock."""
    session = AsyncMock()
    row = RateLimitRow(key="k", count=5, window_start=datetime.now(UTC))
    result = MagicMock()
    result.scalar_one_or_none.return_value = row
    session.execute.return_value = result

    limiter = SQLAlchemyRateLimiter(db_session=session, model=RateLimitRow)
    assert await limiter.check("k", window=60, max_requests=5) is False
    session.commit.assert_awaited()
    assert row.count == 5  # blocked hits don't inflate the counter
