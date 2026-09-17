"""FastAuth: simple flexible auth for FastAPI."""

from .adapters.adapters import Adapter
from .adapters.sqlalchemy import (
    SQLAlchemyJWTAdapter,
    SQLAlchemySessionAdapter,
)
from .config import (
    CookieConfig,
    FastAuthConfig,
    JWTConfig,
    PasswordConfig,
    SessionConfig,
)
from .core import FastAuth
from .models import (
    FastAuthRefreshTokenMixin,
    FastAuthSessionMixin,
    FastAuthUserMixin,
)

__all__ = [
    "Adapter",
    "CookieConfig",
    "FastAuth",
    "FastAuthConfig",
    "FastAuthRefreshTokenMixin",
    "FastAuthSessionMixin",
    "FastAuthUserMixin",
    "JWTConfig",
    "PasswordConfig",
    "SQLAlchemyJWTAdapter",
    "SQLAlchemySessionAdapter",
    "SessionConfig",
]
