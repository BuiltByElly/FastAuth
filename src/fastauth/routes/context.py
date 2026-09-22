"""Shared route context: what strategy modules need from FastAuth."""

from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import Request
from pwdlib import PasswordHash
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import Adapter
from fastauth.config import FastAuthConfig
from fastauth.dependencies.rate_limiter import RateLimiter
from fastauth.hooks.login import LoginFailure
from fastauth.models import (
    FastAuthRefreshTokenMixin,
    FastAuthSessionMixin,
    FastAuthUserMixin,
)


@dataclass
class AuthContext:
    """Per-instance state passed to route registrars (avoids core cycles)."""

    adapter_class: type[Adapter]
    user_model: type[FastAuthUserMixin]
    session_model: type[FastAuthSessionMixin] | None
    db_session_dependency: Callable[[], AsyncGenerator[AsyncSession]]
    signup_schema: type[BaseModel]
    login_schema: type[BaseModel]
    user_response_schema: type[BaseModel]
    strategy: Literal["session", "jwt"]
    config: FastAuthConfig
    rate_limiter: RateLimiter
    signup_hooks: dict[str, Callable[[Any, Request], Awaitable[Any]]]
    login_hooks: dict[str, Callable[[Any, Request], Awaitable[Any]]]
    logout_hooks: dict[str, Callable[[Any], Awaitable[None]]]
    password_hasher: PasswordHash | None = None
    refresh_model: type[FastAuthRefreshTokenMixin] | None = None

    def build_adapter(self, session: AsyncSession) -> Adapter:
        """Wrap the request's session. Sync: no I/O, cheap per-request bind."""
        return self.adapter_class(
            db_session=session,
            user_model=self.user_model,
            session_model=self.session_model,  # type: ignore[arg-type]
            jwt_config=self.config.jwt,
            refresh_model=self.refresh_model,
            session_expire_days=self.config.session.expire_days,
            password_hasher=self.password_hasher,
        )
