"""Unit tests: OIDC state signing, config guards, and id_token claim checks."""

import time

import pytest
from joserfc import jwt as jose_jwt
from joserfc.errors import (
    BadSignatureError,
    ExpiredTokenError,
    InvalidClaimError,
    MissingClaimError,
)
from joserfc.jwk import RSAKey
from pydantic import ValidationError

from fastauth.adapters.sqlalchemy import SQLAlchemyJWTAdapter, SQLAlchemySessionAdapter
from fastauth.config import FastAuthConfig, OIDCConfig
from fastauth.core import OIDCAuth
from fastauth.oauth.oidc import OIDCProvider, OIDCStateManager
from fastauth.security import build_hasher
from tests.conftest import OIDCAccount, Session, User

OIDC_SECRET = "o" * 40
ISSUER = "https://accounts.idp.example"
REDIRECT_URI = "http://testserver/auth/oidc/google/callback"


# --- state cookie ------------------------------------------------------------


def test_generated_state_roundtrips():
    manager = OIDCStateManager(OIDC_SECRET)
    raw, signed = manager.generate("google")
    assert manager.verify(signed, raw, "google") is True


def test_states_are_fresh_and_unguessable():
    manager = OIDCStateManager(OIDC_SECRET)
    first = manager.generate("google")[0]
    second = manager.generate("google")[0]
    assert first != second
    assert len(first) == 43  # secrets.token_urlsafe(32)


def test_verify_rejects_missing_inputs():
    manager = OIDCStateManager(OIDC_SECRET)
    raw, signed = manager.generate("google")
    assert manager.verify(None, raw, "google") is False
    assert manager.verify(signed, None, "google") is False
    assert manager.verify("", raw, "google") is False


def test_verify_rejects_wrong_provider():
    manager = OIDCStateManager(OIDC_SECRET)
    raw, signed = manager.generate("google")
    assert manager.verify(signed, raw, "microsoft") is False


def test_verify_rejects_state_from_another_secret():
    raw, signed = OIDCStateManager("p" * 40).generate("google")
    assert OIDCStateManager(OIDC_SECRET).verify(signed, raw, "google") is False


def test_verify_rejects_tampered_cookie():
    manager = OIDCStateManager(OIDC_SECRET)
    raw, signed = manager.generate("google")
    payload, *rest = signed.split(".")
    tampered = ("B" if payload[0] != "B" else "C") + payload[1:]
    assert manager.verify(".".join([tampered, *rest]), raw, "google") is False


def test_verify_rejects_mismatched_state_value():
    manager = OIDCStateManager(OIDC_SECRET)
    _, signed = manager.generate("google")
    assert manager.verify(signed, "attacker-guess", "google") is False


def test_verify_rejects_expired_state():
    manager = OIDCStateManager(OIDC_SECRET, max_age=-1)
    raw, signed = manager.generate("google")
    assert manager.verify(signed, raw, "google") is False


# --- config guards -----------------------------------------------------------


@pytest.mark.parametrize(
    "secret", ["short", "o" * 31, "change-me", "secret", "password", "test"]
)
def test_oidc_rejects_short_or_placeholder_secret_keys(secret):
    with pytest.raises(ValidationError):
        OIDCConfig(secret_key=secret)


def test_oidc_config_is_frozen():
    cfg = OIDCConfig(secret_key=OIDC_SECRET)
    with pytest.raises(ValidationError):
        cfg.secret_key = "p" * 40


def test_oidc_auth_requires_oidc_section(get_db):
    with pytest.raises(ValueError, match="config.oidc"):
        OIDCAuth(
            adapter=SQLAlchemySessionAdapter,
            user_model=User,
            oidc_account_model=OIDCAccount,
            strategy="session",
            session_model=Session,
            db_session_dependency=get_db,
            config=FastAuthConfig(),  # oidc=None
        )


def test_session_strategy_requires_session_model(get_db, oidc_config):
    with pytest.raises(ValueError, match="session_model"):
        OIDCAuth(
            adapter=SQLAlchemySessionAdapter,
            user_model=User,
            oidc_account_model=OIDCAccount,
            strategy="session",
            db_session_dependency=get_db,
            config=FastAuthConfig(oidc=oidc_config),
        )


def test_jwt_strategy_requires_refresh_model(get_db, oidc_config):
    with pytest.raises(ValueError, match="refresh_model"):
        OIDCAuth(
            adapter=SQLAlchemyJWTAdapter,
            user_model=User,
            oidc_account_model=OIDCAccount,
            strategy="jwt",
            db_session_dependency=get_db,
            config=FastAuthConfig(oidc=oidc_config),
        )


def test_noncompliant_models_fail_fast(get_db, oidc_config):
    """Startup errors, not first-request crashes."""

    class NotAUser:
        pass

    with pytest.raises(TypeError, match="user_model"):
        OIDCAuth(
            adapter=SQLAlchemySessionAdapter,
            user_model=NotAUser,
            oidc_account_model=OIDCAccount,
            strategy="session",
            session_model=Session,
            db_session_dependency=get_db,
            config=FastAuthConfig(oidc=oidc_config),
        )


# --- id_token validation -----------------------------------------------------


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    async def raise_for_status(self):
        return None


def _fake_httpx_client(jwks):
    """Stands in for `httpx2.AsyncClient`: only ever serves the JWKS."""

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

        async def get(self, url):
            return _FakeResponse(jwks)

    return _Client


@pytest.fixture
def provider():
    """OIDCProvider with pre-fetched metadata (no discovery request)."""
    oidc_provider = OIDCProvider(
        name="google",
        client_id="cid",
        client_secret="sec",
        metadata_url="https://idp.example/.well-known/openid-configuration",
    )
    oidc_provider._metadata = {
        "issuer": ISSUER,
        "authorization_endpoint": "https://idp.example/authorize",
        "token_endpoint": "https://idp.example/token",
        "jwks_uri": "https://idp.example/jwks",
    }
    return oidc_provider


@pytest.fixture
def rsa_key():
    return RSAKey.generate_key(parameters={"kid": "k1"})


def _claims(**overrides):
    now = int(time.time())
    claims = {
        "sub": "sub-1",
        "iss": ISSUER,
        "aud": "cid",
        "iat": now,
        "exp": now + 300,
        "email": "u@example.com",
        "email_verified": True,
        "name": "Test User",
        "picture": "https://idp.example/avatar.png",
        "hd": "example.com",
    }
    claims.update(overrides)
    return claims


def _sign(claims, key):
    return jose_jwt.encode({"alg": "RS256", "kid": "k1", "typ": "JWT"}, claims, key)


def _stub_token(monkeypatch, id_token, signing_key, jwks_key):
    """Wire token endpoint + JWKS so `fetch_user_info` runs for real."""

    async def _fetch_token(self, url, code=None, **kwargs):
        return {"id_token": id_token, "access_token": "at", "token_type": "Bearer"}

    monkeypatch.setattr(
        "fastauth.oauth.oidc.AsyncOAuth2Client.fetch_token", _fetch_token
    )
    monkeypatch.setattr(
        "fastauth.oauth.oidc.httpx2.AsyncClient",
        _fake_httpx_client({"keys": [jwks_key.as_dict()]}),
    )


async def test_valid_id_token_is_normalized(monkeypatch, provider, rsa_key):
    _stub_token(monkeypatch, _sign(_claims(), rsa_key), rsa_key, rsa_key)
    info = await provider.fetch_user_info("code", REDIRECT_URI)
    assert info.provider == "google"
    assert info.provider_user_id == "sub-1"
    assert info.email == "u@example.com"
    assert info.email_verified is True
    assert info.avatar_url == "https://idp.example/avatar.png"
    # Non-standard claims are carried through, never dropped silently.
    assert info.others is not None
    assert info.others["hd"] == "example.com"


@pytest.mark.parametrize(
    ("mutate", "expected"),
    [
        (lambda claims: {**claims, "iss": "https://evil.example"}, InvalidClaimError),
        (lambda claims: {**claims, "aud": "other-client"}, InvalidClaimError),
        (lambda claims: {**claims, "exp": int(time.time()) - 60}, ExpiredTokenError),
        (
            lambda claims: {key: v for key, v in claims.items() if key != "exp"},
            MissingClaimError,
        ),
    ],
)
async def test_id_token_with_bad_claims_is_rejected(
    monkeypatch, provider, rsa_key, mutate, expected
):
    _stub_token(monkeypatch, _sign(mutate(_claims()), rsa_key), rsa_key, rsa_key)
    with pytest.raises(expected):
        await provider.fetch_user_info("code", REDIRECT_URI)


async def test_id_token_signed_by_unknown_key_is_rejected(
    monkeypatch, provider, rsa_key
):
    attacker_key = RSAKey.generate_key(parameters={"kid": "k1"})
    _stub_token(monkeypatch, _sign(_claims(), attacker_key), attacker_key, rsa_key)
    with pytest.raises(BadSignatureError):
        await provider.fetch_user_info("code", REDIRECT_URI)


def test_normalize_defaults_email_verified_to_false(provider):
    info = provider._normalize({"sub": "sub-9"})
    assert info.provider_user_id == "sub-9"
    assert info.email_verified is False
    assert info.email is None
    assert info.others is None


# --- adapter guard -----------------------------------------------------------


async def test_oidc_account_model_is_required(session_factory):
    async with session_factory() as session:
        adapter = SQLAlchemySessionAdapter(
            session, User, Session, password_hasher=build_hasher(None)
        )
        with pytest.raises(ValueError, match="oidc_account_model"):
            adapter.require_oidc_account_model()
        with pytest.raises(ValueError, match="oidc_account_model"):
            await adapter.get_oidc_account("google", "sub-1")
