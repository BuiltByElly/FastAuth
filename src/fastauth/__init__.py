"""FastAuth: simple flexible auth for FastAPI."""

from .adapters.sqlalchemy import SQLAlchemyAdapter
from .core import FastAuth
from .models import FastAuthSessionMixin, FastAuthUserMixin

__all__ = ["FastAuth", "FastAuthSessionMixin", "FastAuthUserMixin", "SQLAlchemyAdapter"]
