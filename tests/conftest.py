"""Shared test fixtures: isolated file SQLite, models, app builders.

These fixtures are test-only scaffolding — the `examples/` directory is
never imported or exercised by the suite.
"""

import uuid
from typing import Annotated, Any
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.ext.asyncio import (
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fastauth import JWTAuth, SessionAuth
from fastauth.adapters.sqlalchemy.jwt_adapter import SQLAlchemyJWTAdapter
from fastauth.adapters.sqlalchemy.models import (
    FastAuthOAuthAccountMixin,
    FastAuthPasswordResetTokensMixin,
    FastAuthRateLimitMixin,
    FastAuthRefreshTokenMixin,
    FastAuthSessionMixin,
    FastAuthUserMixin,
)
from fastauth.adapters.sqlalchemy.session_adapter import SQLAlchemySessionAdapter
from fastauth.config import (
    CookieConfig,
    FastAuthConfig,
    JWTConfig,
    OAuth2Config,
    OAuth2ProviderConfig,
    OIDCConfig,
    OIDCProviderConfig,
    RateLimitConfig,
)
from fastauth.core import OAuth2Auth, OIDCAuth

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


class PasswordResetToken(Base, FastAuthPasswordResetTokensMixin):
    """Test password-reset-token table linked to User."""

    __tablename__ = "password_reset_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))


class ExtraPasswordResetToken(Base, FastAuthPasswordResetTokensMixin):
    """Reset-token table linked to ExtraUser (hook-matrix apps)."""

    __tablename__ = "extra_password_reset_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("extra_users.id"))


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


class OIDCAccount(Base, FastAuthOAuthAccountMixin):
    """Test OIDC-account row linking a provider identity to a User."""

    __tablename__ = "oidc_accounts"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)

    __table_args__ = (
        UniqueConstraint(
            "provider", "provider_user_id", name="uq_oidc_provider_account"
        ),
    )


class OAuth2Account(Base, FastAuthOAuthAccountMixin):
    """Test OAuth2-account row linking a provider identity to a User."""

    __tablename__ = "oauth2_accounts"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)

    __table_args__ = (
        UniqueConstraint(
            "provider", "provider_user_id", name="uq_oauth2_provider_account"
        ),
    )


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


@pytest.fixture
def oidc_config():
    """One registered 'google' provider; the IdP itself is always stubbed."""
    return OIDCConfig(
        secret_key="o" * 40,
        providers=[
            OIDCProviderConfig(
                name="google",
                client_id="test-client-id",
                client_secret="test-client-secret",
                redirect_uri="http://testserver/auth/oidc/google/callback",
                metadata_url="https://idp.example/.well-known/openid-configuration",
            )
        ],
    )


@pytest.fixture
def oidc_test_config(oidc_config):
    """Non-secure-cookie, rate-limit-free config for OIDC flow tests.

    Same rationale as `test_config`: strict HTTP clients withhold Secure
    cookies over plain http; cookie *flags* are asserted on the raw
    Set-Cookie header in the transport/OIDC security tests.
    """
    return FastAuthConfig(
        cookies=CookieConfig(secure=False),
        rate_limit=RateLimitConfig(enabled=False),
        oidc=oidc_config,
    )


async def map_github_profile(profile: dict):
    """Test mapper: GitHub-style profile JSON -> normalized user info."""
    from fastauth.types import OAuthUserInfo

    return OAuthUserInfo(
        provider="github",
        provider_user_id=str(profile["id"]),
        email=profile.get("email"),
        email_verified=True,
        name=profile.get("name") or profile.get("login"),
        avatar_url=profile.get("avatar_url"),
    )


@pytest.fixture
def oauth2_config():
    """One registered 'github' provider; the IdP itself is always stubbed."""
    return OAuth2Config(
        secret_key="p" * 40,
        providers=[
            OAuth2ProviderConfig(
                name="github",
                client_id="test-client-id",
                client_secret="test-client-secret",
                redirect_uri="http://testserver/auth/oauth2/github/callback",
                authorization_url="https://provider.example/authorize",
                token_url="https://provider.example/token",
                userinfo_url="https://provider.example/user",
                scopes=["read:user"],
                map_profile_to_user=map_github_profile,
            )
        ],
    )


@pytest.fixture
def oauth2_test_config(oauth2_config):
    """Non-secure-cookie, rate-limit-free config for OAuth2 flow tests."""
    return FastAuthConfig(
        cookies=CookieConfig(secure=False),
        rate_limit=RateLimitConfig(enabled=False),
        oauth2=oauth2_config,
    )


def build_session_app(get_db, config=None, **kwargs):
    """SessionAuth app with a /protected route behind `auth.current_user`."""
    kwargs.setdefault("password_reset_token_model", PasswordResetToken)
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
    kwargs.setdefault("password_reset_token_model", PasswordResetToken)
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


def build_oidc_app(get_db, config=None, strategy="session", **kwargs):
    """OIDCAuth app with a /protected route behind `auth.current_user`.

    `strategy` picks the credential backend ("session" or "jwt") and the
    model it needs. The IdP is stubbed with `stub_oidc_provider` — nothing
    here ever reaches the network.
    """
    if strategy == "session":
        kwargs.setdefault("session_model", Session)
        adapter = SQLAlchemySessionAdapter
    else:
        kwargs.setdefault("refresh_model", RefreshToken)
        adapter = SQLAlchemyJWTAdapter
    auth = OIDCAuth(
        adapter=adapter,
        user_model=User,
        oauth_account_model=OIDCAccount,
        db_session_dependency=get_db,
        strategy=strategy,
        config=config,
        **kwargs,
    )
    app = FastAPI()
    app.include_router(auth.router)

    @app.get("/protected")
    async def protected(user: Annotated[Any, Depends(auth.current_user)]):
        return {"email": user.email}

    return app, auth


def build_oauth2_app(get_db, config=None, strategy="session", **kwargs):
    """OAuth2Auth app with a /protected route behind `auth.current_user`.

    Mirrors `build_oidc_app`: `strategy` picks the credential backend, the
    IdP is stubbed with `stub_oauth2_provider` — nothing reaches the network.
    """
    if strategy == "session":
        kwargs.setdefault("session_model", Session)
        adapter = SQLAlchemySessionAdapter
    else:
        kwargs.setdefault("refresh_model", RefreshToken)
        adapter = SQLAlchemyJWTAdapter
    auth = OAuth2Auth(
        adapter=adapter,
        user_model=User,
        oauth_account_model=OAuth2Account,
        db_session_dependency=get_db,
        strategy=strategy,
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


def stub_oidc_provider(
    monkeypatch,
    *,
    sub="sub-1",
    email="u@example.com",
    email_verified=True,
    name="Test User",
):
    """Stub the IdP: authorize redirect + user-info fetch, zero network.

    Patches `OIDCProvider` at the class level, so every provider registered
    on the app under test routes through here.
    """
    from fastauth.oauth.oidc import OIDCProvider
    from fastauth.types import OAuthUserInfo

    async def _authorize(self, redirect_uri, state):
        return (
            f"https://idp.example/authorize?client_id={self.client_id}"
            f"&redirect_uri={redirect_uri}&state={state}"
        )

    async def _fetch_user_info(self, code, redirect_uri):
        return OAuthUserInfo(
            provider=self.name,
            provider_user_id=sub,
            email=email,
            email_verified=email_verified,
            name=name,
            avatar_url=None,
        )

    monkeypatch.setattr(OIDCProvider, "get_authorize_url", _authorize)
    monkeypatch.setattr(OIDCProvider, "fetch_user_info", _fetch_user_info)


def oidc_begin(client, provider="google"):
    """Start an OIDC login: assert the IdP redirect and return its raw state."""
    response = client.get(f"/auth/oidc/{provider}/login")
    assert response.status_code == 307, response.text
    location = response.headers["location"]
    return parse_qs(urlparse(location).query)["state"][0]


def stub_oauth2_provider(
    monkeypatch,
    *,
    provider_user_id="gh-1",
    email="u@example.com",
    access_token="provider-at",
):
    """Stub the OAuth2 IdP: authorize redirect + token/userinfo fetch.

    Patches `OAuth2Provider` at the class level, so every provider registered
    on the app under test routes through here. Returns OAuth2LoginResult —
    the provider's own tokens are carried on it, never persisted.
    """
    from fastauth.oauth.oauth2 import OAuth2Provider
    from fastauth.types import OAuth2LoginResult, OAuthUserInfo

    async def _authorize(self, redirect_uri, state):
        return (
            f"https://provider.example/authorize?client_id={self.client_id}"
            f"&redirect_uri={redirect_uri}&state={state}"
        )

    async def _fetch_user_info(self, code, redirect_uri):
        return OAuth2LoginResult(
            user_info=OAuthUserInfo(
                provider=self.name,
                provider_user_id=provider_user_id,
                email=email,
                email_verified=True,
                name="Test User",
                avatar_url=None,
            ),
            access_token=access_token,
            refresh_token=None,
            expires_at=None,
        )

    monkeypatch.setattr(OAuth2Provider, "get_authorize_url", _authorize)
    monkeypatch.setattr(OAuth2Provider, "fetch_user_info", _fetch_user_info)


def oauth2_begin(client, provider="github"):
    """Start an OAuth2 login: assert the provider redirect, return raw state."""
    response = client.get(f"/auth/oauth2/{provider}/login")
    assert response.status_code == 307, response.text
    location = response.headers["location"]
    return parse_qs(urlparse(location).query)["state"][0]


__all__ = [
    "TEST_SECRET",
    "Base",
    "ExtraPasswordResetToken",
    "ExtraUser",
    "OAuth2Account",
    "OIDCAccount",
    "PasswordResetToken",
    "RateLimitRow",
    "RefreshToken",
    "Session",
    "User",
    "build_jwt_app",
    "build_oauth2_app",
    "build_oidc_app",
    "build_session_app",
    "cookie_value",
    "create_user",
    "map_github_profile",
    "oauth2_begin",
    "oidc_begin",
    "stub_oauth2_provider",
    "stub_oidc_provider",
]
