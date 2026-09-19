"""
(Do not import directly)
Cookie helpers: one naming convention for both strategies.

Session strategy stores the session id in ``SESSION_COOKIE_NAME``.
JWT strategy stores the refresh token in ``REFRESH_COOKIE_NAME`` only —
the access token always travels in the ``Authorization`` header, never
in a cookie (keeps its lifetime short and out of automatic transport).

All cookies are ``HttpOnly`` (no JS access — non-negotiable for tokens),
``Secure`` and ``SameSite`` by default. ``Secure`` cookies do work on
``http://localhost`` in modern browsers, so local dev is unaffected.
"""

from typing import Literal

from fastapi import Response

from fastauth.config import CookieConfig

SESSION_COOKIE_NAME = "fastauth_session"
REFRESH_COOKIE_NAME = "fastauth_refresh"

SESSION_COOKIE_MAX_AGE = 7 * 24 * 60 * 60
REFRESH_COOKIE_MAX_AGE = 7 * 24 * 60 * 60

SameSite = Literal["lax", "strict", "none"]


def _check_samesite(samesite: SameSite, secure: bool) -> None:
    """Reject ``SameSite=None`` without ``Secure`` (browsers drop it)."""
    if samesite == "none" and not secure:
        msg = "SameSite=None requires secure=True, or browsers reject the cookie."
        raise ValueError(msg)


def set_session_cookie(
    response: Response,
    session_id: str,
    *,
    name: str = SESSION_COOKIE_NAME,
    max_age: int = SESSION_COOKIE_MAX_AGE,
    secure: bool = True,
    samesite: SameSite = "lax",
    path: str = "/",
    domain: str | None = None,
) -> None:
    """Store the session id in an HttpOnly cookie (session strategy)."""
    _check_samesite(samesite, secure)
    response.set_cookie(
        name,
        session_id,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite=samesite,
        path=path,
        domain=domain,
    )


def set_refresh_cookie(
    response: Response,
    refresh_token: str,
    *,
    name: str = REFRESH_COOKIE_NAME,
    max_age: int = REFRESH_COOKIE_MAX_AGE,
    secure: bool = True,
    samesite: SameSite = "lax",
    path: str = "/",
    domain: str | None = None,
) -> None:
    """Store the refresh token in an HttpOnly cookie (JWT strategy)."""
    _check_samesite(samesite, secure)
    response.set_cookie(
        name,
        refresh_token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite=samesite,
        path=path,
        domain=domain,
    )


def clear_session_cookie(
    response: Response,
    *,
    name: str = SESSION_COOKIE_NAME,
    secure: bool = True,
    samesite: SameSite = "lax",
    path: str = "/",
    domain: str | None = None,
) -> None:
    """Delete the session cookie. Name/path/flags must match the setter."""
    response.delete_cookie(
        name,
        path=path,
        domain=domain,
        secure=secure,
        httponly=True,
        samesite=samesite,
    )


def clear_refresh_cookie(
    response: Response,
    *,
    name: str = REFRESH_COOKIE_NAME,
    secure: bool = True,
    samesite: SameSite = "lax",
    path: str = "/",
    domain: str | None = None,
) -> None:
    """Delete the refresh cookie. Name/path/flags must match the setter."""
    response.delete_cookie(
        name,
        path=path,
        domain=domain,
        secure=secure,
        httponly=True,
        samesite=samesite,
    )


def session_cookie_kwargs(cfg: CookieConfig, *, max_age: int) -> dict:
    """Expand a CookieConfig into set_session_cookie kwargs (name/flags)."""
    return {
        "name": cfg.session_cookie_name,
        "max_age": max_age,
        "secure": cfg.secure,
        "samesite": cfg.samesite,
        "path": cfg.path,
        "domain": cfg.domain,
    }


def refresh_cookie_kwargs(cfg: CookieConfig, *, max_age: int) -> dict:
    """Expand a CookieConfig into set_refresh_cookie kwargs (name/flags)."""
    return {
        "name": cfg.refresh_cookie_name,
        "max_age": max_age,
        "secure": cfg.secure,
        "samesite": cfg.samesite,
        "path": cfg.path,
        "domain": cfg.domain,
    }


def clear_cookie_kwargs(cfg: CookieConfig) -> dict:
    """Expand a CookieConfig into clear_* kwargs (must match the setter)."""
    return {
        "secure": cfg.secure,
        "samesite": cfg.samesite,
        "path": cfg.path,
        "domain": cfg.domain,
    }
