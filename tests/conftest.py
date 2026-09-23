"""Shared test fixtures: isolated file SQLite, models, app builders.

These fixtures are test-only scaffolding — the `examples/` directory is
never imported or exercised by the suite.
"""

import uuid
from typing import Annotated, Any

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import ForeignKey, String
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fastauth import JWTAuth, SessionAuth
from fastauth.adapters.sqlalchemy.jwt_adapter import SQLAlchemyJWTAdapter
from fastauth.adapters.sqlalchemy.models import (
    FastAuthRateLimitMixin,
    FastAuthRefreshTokenMixin,
    FastAuthSessionMixin,
    FastAuthUserMixin,
)
from fastauth.adapters.sqlalchemy.session_adapter import SQLAlchemySessionAdapter
from fastauth.config import CookieConfig, FastAuthConfig, JWTConfig, RateLimitConfig

TEST_SECRET = "0123456789abcdef" * 3  # 48 chars, not a placeholder


class Base(DeclarativeBase):
    """Declarative base for test-only models."""


class User(Base, FastAuthUserMixin):
    """Test user table."""

    __tablename__ = "users"


class Session(Base, FastAuthSessionMixin):
    """Test session table linked to User."""

    __tablename__ = "sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))


class RefreshToken(Base, FastAuthRefreshTokenMixin):
    """Test refresh-token table linked to User."""

    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))


class RateLimitRow(Base, FastAuthRateLimitMixin):
    """Test rate-limit counter table."""

    __tablename__ = "rate_limits"


class ExtraUser(Base, FastAuthUserMixin):
    """User with dev-tagged extra columns for dynamic-schema tests."""

    __tablename__ = "extra_users"

    role: Mapped[str] = mapped_column(
        String(20), info={"fastauth_input": True, "fastauth_returned": True}
    )
    bio: Mapped[str | None] = mapped_column(
        String, info={"fastauth_input": True, "fastauth_returned": False}
    )
    internal_note: Mapped[str | None] = mapped_column(String, nullable=True)


@pytest.fixture
def db_url(tmp_path):
    """Unique SQLite file per test — full isolation, no shared state."""
    return f"sqlite+aiosqlite:///{tmp_path}/test.db"


@pytest.fixture
def engine(db_url):
    """Async engine for one test."""
    return create_async_engine(db_url)


@pytest.fixture
async def tables(engine):
    """Create all tables, yield, then dispose the engine."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


@pytest.fixture
def session_factory(engine, tables):
    """Session factory bound to the test engine."""
    return async_sessionmaker(engine, expire_on_commit=False)


@pytest.fixture
def get_db(session_factory):
    """FastAPI dependency yielding request-scoped sessions."""

    async def _get_db():
        async with session_factory() as session:
            yield session

    return _get_db


@pytest.fixture
def test_config():
    """Non-secure-cookie, rate-limit-free config for flow tests.

    `secure=False` because strict HTTP clients (httpx/TestClient) withhold
    Secure cookies over plain http; cookie *flags* are asserted separately
    in the transport security tests.
    """
    return FastAuthConfig(
        cookies=CookieConfig(secure=False),
        rate_limit=RateLimitConfig(enabled=False),
    )


@pytest.fixture
def jwt_config():
    """Valid JWT config for strategy tests."""
    return JWTConfig(secret_key=TEST_SECRET)


def build_session_app(get_db, config=None, **kwargs):
    """SessionAuth app with a /protected route behind `auth.current_user`."""
    auth = SessionAuth(
        adapter=SQLAlchemySessionAdapter,
        user_model=User,
        session_model=Session,
        db_session_dependency=get_db,
        config=config,
        **kwargs,
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/protected")
    async def protected(user: Annotated[Any, Depends(auth.current_user)]):
        return {"email": user.email}

    return app, auth


def build_jwt_app(get_db, config=None, **kwargs):
    """JWTAuth app with a /protected route behind `auth.current_user`."""
    auth = JWTAuth(
        adapter=SQLAlchemyJWTAdapter,
        user_model=User,
        refresh_model=RefreshToken,
        db_session_dependency=get_db,
        config=config,
        **kwargs,
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/protected")
    async def protected(user: Annotated[Any, Depends(auth.current_user)]):
        return {"email": user.email}

    return app, auth


@pytest.fixture
def session_client(get_db, test_config):
    """TestClient for a session-strategy app (no rate limiting)."""
    app, _ = build_session_app(get_db, config=test_config)
    with TestClient(app) as client:
        yield client


@pytest.fixture
def jwt_client(get_db, test_config, jwt_config):
    """TestClient for a JWT-strategy app (no rate limiting)."""
    config = test_config.model_copy(update={"jwt": jwt_config})
    app, _ = build_jwt_app(get_db, config=config)
    with TestClient(app) as client:
        yield client


async def create_user(session_factory, email="u@example.com", password="long-enough"):
    """Insert a user directly, bypassing HTTP."""
    from fastauth.security import hash_password

    async with session_factory() as session:
        user = User(email=email, hashed_password=hash_password(password))
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


def cookie_value(set_cookie_header):
    """First `name=value` pair of a Set-Cookie header, unquoted."""
    return set_cookie_header.split(";")[0].split("=", 1)[1].strip('"')


__all__ = [
    "TEST_SECRET",
    "Base",
    "ExtraUser",
    "RateLimitRow",
    "RefreshToken",
    "Session",
    "User",
    "build_jwt_app",
    "build_session_app",
    "cookie_value",
    "create_user",
]
