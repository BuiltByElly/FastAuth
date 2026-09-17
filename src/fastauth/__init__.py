"""FastAuth: simple flexible auth for FastAPI."""

from .adapters.adapters import Adapter, SessionT, UserT
from .adapters.sqlalchemy import (
    SQLAlchemyJWTAdapter,
    SQLAlchemySessionAdapter,
)
from .config import JWTConfig
from .cookies import (
    REFRESH_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    clear_refresh_cookie,
    clear_session_cookie,
    set_refresh_cookie,
    set_session_cookie,
)
from .core import FastAuth
from .dependencies import (
    bearer_scheme,
    current_refresh_token,
    jwt_current_user,
    session_current_user,
)
from .models import (
    FastAuthRefreshTokenMixin,
    FastAuthSessionMixin,
    FastAuthUserMixin,
)

__all__ = [
    "Adapter",
    "FastAuth",
    "FastAuthRefreshTokenMixin",
    "FastAuthSessionMixin",
    "FastAuthUserMixin",
    "JWTConfig",
    "REFRESH_COOKIE_NAME",
    "SESSION_COOKIE_NAME",
    "SQLAlchemyJWTAdapter",
    "SQLAlchemySessionAdapter",
    "SessionT",
    "UserT",
    "bearer_scheme",
    "clear_refresh_cookie",
    "clear_session_cookie",
    "current_refresh_token",
    "jwt_current_user",
    "session_current_user",
    "set_refresh_cookie",
    "set_session_cookie",
]
