"""Unit tests: every config section validates its invariants."""

import pytest
from pydantic import ValidationError

from fastauth.config import (
    CookieConfig,
    FastAuthConfig,
    JWTConfig,
    PasswordConfig,
    RateLimitConfig,
    SessionConfig,
)


def test_defaults_are_secure_and_working():
    cfg = FastAuthConfig()
    assert cfg.session.expire_days == 7
    assert cfg.cookies.session_cookie_name == "fastauth_session"
    assert cfg.cookies.refresh_cookie_name == "fastauth_refresh"
    assert cfg.cookies.secure is True
    assert cfg.cookies.samesite == "lax"
    assert cfg.cookies.path == "/"
    assert cfg.cookies.domain is None
    assert cfg.password.min_length == 8
    assert cfg.password.max_length == 128
    assert cfg.password.hash_schemes is None
    assert cfg.jwt is None
    assert cfg.rate_limit.enabled is True
    assert cfg.rate_limit.storage == "memory"


def test_config_is_frozen():
    cfg = FastAuthConfig()
    with pytest.raises(ValidationError):
        cfg.session.expire_days = 3


def test_model_copy_override_style():
    cfg = FastAuthConfig().model_copy(update={"session": SessionConfig(expire_days=3)})
    assert cfg.session.expire_days == 3
    assert cfg.cookies.session_cookie_name == "fastauth_session"


@pytest.mark.parametrize("secret", ["short", "change-me", "Secret", "PASSWORD", "test"])
def test_jwt_rejects_short_or_placeholder_secrets(secret):
    with pytest.raises(ValidationError):
        JWTConfig(secret_key=secret)


def test_jwt_rejects_bad_algorithm():
    with pytest.raises(ValidationError):
        JWTConfig(secret_key="x" * 40, algorithm="none")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"access_token_expire_minutes": 0},
        {"access_token_expire_minutes": 31},
        {"refresh_token_expire_days": 0},
        {"refresh_token_expire_days": 31},
    ],
)
def test_jwt_rejects_out_of_range_lifetimes(kwargs):
    with pytest.raises(ValidationError):
        JWTConfig(secret_key="x" * 40, **kwargs)


def test_jwt_accepts_custom_values():
    cfg = JWTConfig(
        secret_key="y" * 40,
        algorithm="HS384",
        access_token_expire_minutes=5,
        refresh_token_expire_days=1,
    )
    assert cfg.algorithm == "HS384"
    assert cfg.access_token_expire_minutes == 5


@pytest.mark.parametrize("days", [0, -1, 31])
def test_session_rejects_out_of_range_expiry(days):
    with pytest.raises(ValidationError):
        SessionConfig(expire_days=days)


@pytest.mark.parametrize("name", ["", "a;b", "a b", "a=b", 'a"b', "a,b"])
def test_cookie_rejects_unsafe_names(name):
    with pytest.raises(ValidationError):
        CookieConfig(session_cookie_name=name)
    with pytest.raises(ValidationError):
        CookieConfig(refresh_cookie_name=name)


def test_cookie_rejects_samesite_none_without_secure():
    with pytest.raises(ValidationError):
        CookieConfig(samesite="none", secure=False)
    # None + Secure is the valid combination.
    assert CookieConfig(samesite="none", secure=True).samesite == "none"


def test_password_rejects_inconsistent_lengths():
    with pytest.raises(ValidationError):
        PasswordConfig(min_length=20, max_length=10)
    with pytest.raises(ValidationError):
        PasswordConfig(min_length=0)


def test_rate_limit_custom_rules_override():
    cfg = RateLimitConfig(custom_rules={"/login": (10, 2)})
    assert cfg.custom_rules["/login"] == (10, 2)
    # A supplied dict replaces (not merges) the defaults.
    assert "/signup" not in cfg.custom_rules
