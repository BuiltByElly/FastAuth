"""Unit tests: cookie helpers set secure attributes and clear correctly."""

import pytest
from fastapi import Response

from fastauth.cookies import (
    REFRESH_COOKIE_MAX_AGE,
    REFRESH_COOKIE_NAME,
    SESSION_COOKIE_MAX_AGE,
    SESSION_COOKIE_NAME,
    clear_cookie_kwargs,
    clear_refresh_cookie,
    clear_session_cookie,
    refresh_cookie_kwargs,
    session_cookie_kwargs,
    set_refresh_cookie,
    set_session_cookie,
)
from fastauth.config import CookieConfig


def _header(response):
    return response.headers["set-cookie"]


def test_set_session_cookie_defaults_are_secure():
    header = _header(_set_session())
    assert f"{SESSION_COOKIE_NAME}=sid123" in header
    assert "HttpOnly" in header
    assert "Secure" in header
    assert "SameSite=lax" in header
    assert "Path=/" in header
    assert f"Max-Age={SESSION_COOKIE_MAX_AGE}" in header


def _set_session(**kwargs):
    response = Response()
    set_session_cookie(response, "sid123", **kwargs)
    return response


def test_set_refresh_cookie_defaults_are_secure():
    response = Response()
    set_refresh_cookie(response, "tok")
    header = _header(response)
    assert f"{REFRESH_COOKIE_NAME}=tok" in header
    assert "HttpOnly" in header
    assert "Secure" in header
    assert f"Max-Age={REFRESH_COOKIE_MAX_AGE}" in header


def test_cookie_helpers_honor_overrides():
    response = Response()
    set_session_cookie(
        response, "v", name="custom", max_age=99, secure=False,
        samesite="strict", path="/auth", domain="example.com",
    )
    header = _header(response)
    assert "custom=v" in header
    assert "Max-Age=99" in header
    assert "Secure" not in header
    assert "SameSite=strict" in header
    assert "Path=/auth" in header
    assert "Domain=example.com" in header


def test_samesite_none_without_secure_raises():
    with pytest.raises(ValueError, match="SameSite=None"):
        set_session_cookie(Response(), "v", samesite="none", secure=False)
    with pytest.raises(ValueError, match="SameSite=None"):
        set_refresh_cookie(Response(), "v", samesite="none", secure=False)


@pytest.mark.parametrize("clear", [clear_session_cookie, clear_refresh_cookie])
def test_clear_helpers_emit_deletion(clear):
    response = Response()
    clear(response)
    header = _header(response)
    # Starlette deletes by expiring immediately.
    assert "Max-Age=0" in header


def test_clear_uses_matching_name():
    response = Response()
    clear_session_cookie(response, name="custom")
    assert "custom=" in _header(response)


def test_kwargs_expanders_mirror_config():
    cfg = CookieConfig(
        session_cookie_name="s", refresh_cookie_name="r",
        secure=False, samesite="strict", path="/a", domain="example.com",
    )
    assert session_cookie_kwargs(cfg, max_age=10) == {
        "name": "s", "max_age": 10, "secure": False,
        "samesite": "strict", "path": "/a", "domain": "example.com",
    }
    assert refresh_cookie_kwargs(cfg, max_age=20)["name"] == "r"
    assert refresh_cookie_kwargs(cfg, max_age=20)["max_age"] == 20
    cleared = clear_cookie_kwargs(cfg)
    assert cleared == {
        "secure": False, "samesite": "strict",
        "path": "/a", "domain": "example.com",
    }
