"""Cookie helpers: one naming convention for both strategies.

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
    max_age: int = SESSION_COOKIE_MAX_AGE,
    secure: bool = True,
    samesite: SameSite = "lax",
    path: str = "/",
) -> None:
    """Store the session id in an HttpOnly cookie (session strategy)."""
    _check_samesite(samesite, secure)
    response.set_cookie(
        SESSION_COOKIE_NAME,
        session_id,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite=samesite,
        path=path,
    )


def set_refresh_cookie(
    response: Response,
    refresh_token: str,
    *,
    max_age: int = REFRESH_COOKIE_MAX_AGE,
    secure: bool = True,
    samesite: SameSite = "lax",
    path: str = "/",
) -> None:
    """Store the refresh token in an HttpOnly cookie (JWT strategy)."""
    _check_samesite(samesite, secure)
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        refresh_token,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite=samesite,
        path=path,
    )


def clear_session_cookie(
    response: Response,
    *,
    secure: bool = True,
    samesite: SameSite = "lax",
    path: str = "/",
) -> None:
    """Delete the session cookie. Path/flags must match the setter."""
    response.delete_cookie(
        SESSION_COOKIE_NAME,
        path=path,
        secure=secure,
        httponly=True,
        samesite=samesite,
    )


def clear_refresh_cookie(
    response: Response,
    *,
    secure: bool = True,
    samesite: SameSite = "lax",
    path: str = "/",
) -> None:
    """Delete the refresh cookie. Path/flags must match the setter."""
    response.delete_cookie(
        REFRESH_COOKIE_NAME,
        path=path,
        secure=secure,
        httponly=True,
        samesite=samesite,
    )
