"""Unit tests: OAuth2 config guards, provider mapping, and auth init.

State signing is NOT re-tested here — `OAuth2Auth` shares `OAuthStateManager`
with `OIDCAuth`, already covered exhaustively in `test_oidc.py`.
"""

import pytest
from pydantic import ValidationError

from fastauth.adapters.sqlalchemy import SQLAlchemyJWTAdapter, SQLAlchemySessionAdapter
from fastauth.config import FastAuthConfig, OAuth2Config
from fastauth.core import OAuth2Auth
from fastauth.oauth.oauth2 import OAuth2Provider
from fastauth.security import build_hasher
from fastauth.types import OAuthUserInfo
from tests.conftest import (
    OAuth2Account,
    Session,
    User,
    map_github_profile,
)

OAUTH2_SECRET = "p" * 40
REDIRECT_URI = "http://testserver/auth/oauth2/github/callback"


def _provider(**overrides):
    values = {
        "name": "github",
        "client_id": "cid",
        "client_secret": "sec",
        "authorization_url": "https://provider.example/authorize",
        "token_url": "https://provider.example/token",
        "userinfo_url": "https://provider.example/user",
        "map_profile_to_user": map_github_profile,
    }
    values.update(overrides)
    return OAuth2Provider(**values)


# --- config guards -----------------------------------------------------------


@pytest.mark.parametrize(
    "secret", ["short", "p" * 31, "change-me", "secret", "password", "test"]
)
def test_oauth2_rejects_short_or_placeholder_secret_keys(secret):
    with pytest.raises(ValidationError):
        OAuth2Config(secret_key=secret)


def test_oauth2_config_is_frozen(oauth2_config):
    with pytest.raises(ValidationError):
        oauth2_config.secret_key = "q" * 40


def test_oauth2_auth_requires_oauth2_section(get_db):
    with pytest.raises(ValueError, match="config.oauth2"):
        OAuth2Auth(
            adapter=SQLAlchemySessionAdapter,
            user_model=User,
            oauth_account_model=OAuth2Account,
            strategy="session",
            session_model=Session,
            db_session_dependency=get_db,
            config=FastAuthConfig(),  # oauth2=None
        )


def test_session_strategy_requires_session_model(get_db, oauth2_config):
    with pytest.raises(ValueError, match="session_model"):
        OAuth2Auth(
            adapter=SQLAlchemySessionAdapter,
            user_model=User,
            oauth_account_model=OAuth2Account,
            strategy="session",
            db_session_dependency=get_db,
            config=FastAuthConfig(oauth2=oauth2_config),
        )


def test_jwt_strategy_requires_refresh_model(get_db, oauth2_config):
    with pytest.raises(ValueError, match="refresh_model"):
        OAuth2Auth(
            adapter=SQLAlchemyJWTAdapter,
            user_model=User,
            oauth_account_model=OAuth2Account,
            strategy="jwt",
            db_session_dependency=get_db,
            config=FastAuthConfig(oauth2=oauth2_config),
        )


def test_noncompliant_models_fail_fast(get_db, oauth2_config):
    """Startup errors, not first-request crashes."""

    class NotAUser:
        pass

    with pytest.raises(TypeError, match="user_model"):
        OAuth2Auth(
            adapter=SQLAlchemySessionAdapter,
            user_model=NotAUser,
            oauth_account_model=OAuth2Account,
            strategy="session",
            session_model=Session,
            db_session_dependency=get_db,
            config=FastAuthConfig(oauth2=oauth2_config),
        )


# --- provider ----------------------------------------------------------------


async def test_authorize_url_carries_state_scope_and_extra_params():
    provider = _provider(scope="read:user", extra_authorize_params={"allow_signup": "false"})
    url = await provider.get_authorize_url(REDIRECT_URI, "raw-state")
    assert url.startswith("https://provider.example/authorize?")
    assert "state=raw-state" in url
    assert "read%3Auser" in url or "read:user" in url
    assert "allow_signup=false" in url


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


def _stub_token_and_profile(monkeypatch, profile):
    async def _fetch_token(self, url, code=None, **kwargs):
        return {"access_token": "provider-at", "token_type": "Bearer"}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url, headers=None):
            assert headers["Authorization"] == "Bearer provider-at"
            return _FakeResponse(profile)

    monkeypatch.setattr(
        "fastauth.oauth.oauth2.AsyncOAuth2Client.fetch_token", _fetch_token
    )
    monkeypatch.setattr("fastauth.oauth.oauth2.httpx2.AsyncClient", _Client)


async def test_fetch_user_info_uses_dev_mapper(monkeypatch):
    _stub_token_and_profile(
        monkeypatch,
        {"id": 42, "login": "octocat", "email": "o@example.com"},
    )
    result = await _provider().fetch_user_info("code", REDIRECT_URI)
    assert result.access_token == "provider-at"
    assert result.refresh_token is None
    assert isinstance(result.user_info, OAuthUserInfo)
    assert result.user_info.provider == "github"
    assert result.user_info.provider_user_id == "42"
    assert result.user_info.email == "o@example.com"
    assert result.user_info.name == "octocat"


# --- adapter guard -----------------------------------------------------------


async def test_oauth_account_model_is_required(session_factory):
    async with session_factory() as session:
        adapter = SQLAlchemySessionAdapter(
            session, User, Session, password_hasher=build_hasher(None)
        )
        with pytest.raises(ValueError, match="oauth_account_model"):
            adapter.require_oauth_account_model()
        with pytest.raises(ValueError, match="oauth_account_model"):
            await adapter.get_oauth2_account("github", "gh-1")
