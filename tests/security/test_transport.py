"""Security: transport hardening — cookies, headers, and input gates."""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from fastauth import JWTAuth
from fastauth.adapters.sqlalchemy import SQLAlchemyJWTAdapter
from fastauth.config import (
    CookieConfig,
    FastAuthConfig,
    JWTConfig,
    RateLimitConfig,
)
from tests.conftest import (
    TEST_SECRET,
    RefreshToken,
    User,
    build_jwt_app,
    build_session_app,
)


def _unlimited_secure_config(**overrides):
    """Production cookie flags, rate limiting off (tested separately)."""
    values = {"rate_limit": RateLimitConfig(enabled=False), **overrides}
    return FastAuthConfig(**values)


@pytest.fixture
def secure_session_client(get_db):
    """Session app with default (Secure + Lax + HttpOnly) cookies."""
    app, _ = build_session_app(get_db, config=_unlimited_secure_config())
    with TestClient(app) as client:
        yield client


def test_session_cookie_flags_are_hardened(secure_session_client):
    secure_session_client.post(
        "/auth/signup", json={"email": "u@example.com", "password": "long-enough"}
    )
    response = secure_session_client.post(
        "/auth/login", json={"email": "u@example.com", "password": "long-enough"}
    )
    header = response.headers["set-cookie"]
    assert "HttpOnly" in header  # no JS access → XSS can't steal it
    assert "Secure" in header  # HTTPS only
    assert "SameSite=lax" in header  # no cross-site sends


def test_custom_cookie_name_is_used(get_db):
    config = _unlimited_secure_config(
        cookies=CookieConfig(session_cookie_name="sid", secure=False)
    )
    app, _ = build_session_app(get_db, config=config)
    with TestClient(app) as client:
        client.post("/auth/signup", json={"email": "u@example.com", "password": "long-enough"})
        assert client.cookies.get("sid")
        assert client.cookies.get("fastauth_session") is None


def test_access_token_never_set_as_cookie(get_db, jwt_config):
    """The access token must travel in the header only, never auto-attached."""
    config = _unlimited_secure_config(jwt=jwt_config)
    app, _ = build_jwt_app(get_db, config=config)
    with TestClient(app) as client:
        client.post("/auth/signup", json={"email": "u@example.com", "password": "long-enough"})
        response = client.post(
            "/auth/login", json={"email": "u@example.com", "password": "long-enough"}
        )
        set_cookie = response.headers["set-cookie"]
        assert "fastauth_refresh=" in set_cookie
        assert "access_token" not in set_cookie
        assert response.json()["access_token"] not in set_cookie


def test_bearer_401_carries_www_authenticate(jwt_client):
    response = jwt_client.get("/auth/me")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("password", ["short", "", "1234567"])
def test_short_passwords_rejected_at_boundary(session_client, password):
    response = session_client.post(
        "/auth/signup", json={"email": "u@example.com", "password": password}
    )
    assert response.status_code == 422


def test_password_max_length_enforced(session_client):
    response = session_client.post(
        "/auth/signup", json={"email": "u@example.com", "password": "x" * 129}
    )
    assert response.status_code == 422


@pytest.mark.parametrize("secret", ["short", "change-me", "Secret", "password"])
def test_weak_jwt_secrets_rejected_at_startup(get_db, secret):
    with pytest.raises(ValidationError):
        JWTConfig(secret_key=secret)


def test_jwt_auth_without_jwt_section_rejected(get_db):
    with pytest.raises(ValueError, match="config.jwt"):
        JWTAuth(
            adapter=SQLAlchemyJWTAdapter,
            user_model=User,
            refresh_model=RefreshToken,
            db_session_dependency=get_db,
            config=FastAuthConfig(),  # jwt=None
        )


def test_jwt_auth_supports_custom_secret_config(get_db):
    """Sanity: a well-formed config constructs and serves a token."""
    config = _unlimited_secure_config(jwt=JWTConfig(secret_key=TEST_SECRET))
    app, _ = build_jwt_app(get_db, config=config)
    with TestClient(app) as client:
        assert (
            client.post("/auth/signup", json={"email": "u@example.com", "password": "long-enough"}).status_code
            == 200
        )
        assert len(login(client).json()["access_token"].split(".")) == 3


def login(client):
    return client.post(
        "/auth/login", json={"email": "u@example.com", "password": "long-enough"}
    )


def test_signup_rejects_malformed_email(session_client):
    response = session_client.post(
        "/auth/signup", json={"email": "not-an-email", "password": "long-enough"}
    )
    assert response.status_code == 422
