"""FastAuth: simple flexible auth for FastAPI."""

from .adapters.adapters import Adapter
from .adapters.sqlalchemy import (
    SQLAlchemyJWTAdapter,
    SQLAlchemySessionAdapter,
)
from .config import JWTConfig
from .core import FastAuth
from .dependencies import (
    current_refresh_token,
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
    "SQLAlchemyJWTAdapter",
    "SQLAlchemySessionAdapter",
    "current_refresh_token",
]
