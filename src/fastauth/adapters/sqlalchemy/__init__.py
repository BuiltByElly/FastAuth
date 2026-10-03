"""SQLAlchemy backend for FastAuth: adapters + model mixins."""

from fastauth.adapters.sqlalchemy.jwt_adapter import SQLAlchemyJWTAdapter
from fastauth.adapters.sqlalchemy.models import (
    FastAuthOAuthAccountMixin,
    FastAuthPasswordResetTokensMixin,
    FastAuthRateLimitMixin,
    FastAuthRefreshTokenMixin,
    FastAuthSessionMixin,
    FastAuthUserMixin,
)
from fastauth.adapters.sqlalchemy.session_adapter import SQLAlchemySessionAdapter

__all__ = [
    "FastAuthOAuthAccountMixin",
    "FastAuthPasswordResetTokensMixin",
    "FastAuthRateLimitMixin",
    "FastAuthRefreshTokenMixin",
    "FastAuthSessionMixin",
    "FastAuthUserMixin",
    "SQLAlchemyJWTAdapter",
    "SQLAlchemySessionAdapter",
]
