"""Integration: rate limits enforced on auth routes (memory + database)."""

from typing import Literal

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from fastauth.adapters.rate_limit.sqlalchemy import SQLAlchemyRateLimiter
from fastauth.config import CookieConfig, FastAuthConfig, RateLimitConfig
from fastauth.dependencies.rate_limiter import RateLimiter
from tests.conftest import RateLimitRow, build_session_app


def limited_app(
    get_db,
    rules,
    storage: Literal["memory", "database"] = "memory",
    rate_limiter=None,
    **kwargs,
):
    """Session app with tight per-route rules and insecure cookies for the jar.

    When a ready-made `rate_limiter` is passed it owns behavior, so the
    config section stays default (anything else there would be ignored).
    Otherwise the config drives the limiter FastAuth builds internally.
    """
    if rate_limiter is None:
        rate_limit = RateLimitConfig(storage=storage, custom_rules=rules)
    else:
        rate_limit = RateLimitConfig()
    config = FastAuthConfig(
        cookies=CookieConfig(secure=False),
        rate_limit=rate_limit,
    )
    app, _ = build_session_app(
        get_db, config=config, rate_limiter=rate_limiter, **kwargs
    )
    return app


def login(client, password="wrong-pass-1"):
    return client.post(
        "/auth/login", json={"email": "u@example.com", "password": password}
    )


@pytest.fixture
def memory_app(get_db):
    return limited_app(get_db, {"/login": (60, 3), "/signup": (60, 100)})


def test_memory_login_429_after_budget(memory_app):
    with TestClient(memory_app) as client:
        codes = [login(client).status_code for _ in range(4)]
    assert codes == [401, 401, 401, 429]


def test_memory_signup_rule_independent_budget(get_db):
    app = limited_app(get_db, {"/signup": (60, 2), "/login": (60, 100)})
    with TestClient(app) as client:
        codes = [
            client.post(
                "/auth/signup",
                json={"email": f"u{i}@example.com", "password": "long-enough"},
            ).status_code
            for i in range(3)
        ]
    assert codes == [200, 200, 429]


def test_memory_budgets_are_per_path(get_db):
    app = limited_app(get_db, {"/login": (60, 1), "/signup": (60, 100)})
    with TestClient(app) as client:
        assert login(client).status_code == 401  # spends the /login budget
        assert login(client).status_code == 429
        # /signup budget untouched.
        assert (
            client.post(
                "/auth/signup",
                json={"email": "fresh@example.com", "password": "long-enough"},
            ).status_code
            == 200
        )


def test_database_storage_enforces_limits(get_db):
    app = limited_app(
        get_db,
        {},
        storage="database",
        rate_limiter=RateLimiter(
            rate_limiter_adapter=SQLAlchemyRateLimiter,
            db_session_dependency=get_db,
            rate_limit_model=RateLimitRow,
            rate_limit_config=RateLimitConfig(
                storage="database", custom_rules={"/login": (60, 2)}
            ),
        ),
    )
    with TestClient(app) as client:
        codes = [login(client).status_code for _ in range(3)]
    assert codes == [401, 401, 429]


async def test_database_storage_persists_counters(get_db, session_factory):
    app = limited_app(
        get_db,
        {},
        storage="database",
        rate_limiter=RateLimiter(
            rate_limiter_adapter=SQLAlchemyRateLimiter,
            db_session_dependency=get_db,
            rate_limit_model=RateLimitRow,
            rate_limit_config=RateLimitConfig(
                storage="database", custom_rules={"/login": (60, 100)}
            ),
        ),
    )
    with TestClient(app) as client:
        login(client)
    async with session_factory() as session:
        count = await session.scalar(select(func.count()).select_from(RateLimitRow))
        assert count == 1


def test_database_storage_requires_model_and_adapter(get_db):
    with pytest.raises(ValueError, match="rate_limit_model"):
        limited_app(
            get_db,
            {},
            storage="database",
            rate_limiter=RateLimiter(
                rate_limiter_adapter=SQLAlchemyRateLimiter,
                db_session_dependency=get_db,
                rate_limit_config=RateLimitConfig(storage="database"),
            ),
        )
    with pytest.raises(ValueError, match="rate_limiter_adapter"):
        limited_app(
            get_db,
            {},
            storage="database",
            rate_limiter=RateLimiter(
                rate_limit_config=RateLimitConfig(storage="database"),
                db_session_dependency=get_db,
                rate_limit_model=RateLimitRow,
            ),
        )


def test_disabled_limiter_never_blocks(get_db):
    config = FastAuthConfig(
        cookies=CookieConfig(secure=False),
        rate_limit=RateLimitConfig(enabled=False),
    )
    app, _ = build_session_app(get_db, config=config)
    with TestClient(app) as client:
        codes = [login(client).status_code for _ in range(10)]
    assert codes == [401] * 10


def test_explicit_limiter_wins_over_config_and_warns(get_db):
    """A passed instance owns behavior; a non-default config section warns."""
    limiter = RateLimiter(
        rate_limit_config=RateLimitConfig(custom_rules={"/login": (60, 1)})
    )
    conflicting = FastAuthConfig(
        cookies=CookieConfig(secure=False),
        rate_limit=RateLimitConfig(custom_rules={"/login": (60, 100)}),
    )
    with pytest.warns(UserWarning, match="config.rate_limit section is ignored"):
        app, _ = build_session_app(
            get_db, config=conflicting, rate_limiter=limiter
        )
    with TestClient(app) as client:
        assert login(client).status_code == 401
        # Limiter's rule of 1 wins — not the config's 100.
        assert login(client).status_code == 429


def test_no_warning_when_config_section_untouched(get_db, recwarn):
    limiter = RateLimiter(
        rate_limit_config=RateLimitConfig(custom_rules={"/login": (60, 100)})
    )
    limited_app(get_db, {}, rate_limiter=limiter)
    assert [w for w in recwarn.list if "rate_limit" in str(w.message)] == []
