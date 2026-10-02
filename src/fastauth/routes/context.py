"""Shared route context: what strategy modules need from FastAuth."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from fastapi import Request
from pwdlib import PasswordHash
from pydantic import BaseModel

from fastauth.adapters.adapters import Adapter
from fastauth.config import FastAuthConfig
from fastauth.dependencies.rate_limiter import RateLimiter
from fastauth.oauth.oidc import OIDCProvider, OIDCStateManager


@dataclass
class AuthContext:
    """Per-instance state passed to route registrars (avoids core cycles)."""

    adapter_class: type[Adapter]
    user_model: type[Any]
    db_session_dependency: Callable[[], AsyncGenerator[Any]]
    signup_schema: type[BaseModel]
    login_schema: type[BaseModel]
    user_response_schema: type[BaseModel]
    password_reset_token_schema: type[BaseModel]
    strategy: Literal["session", "jwt"]
    config: FastAuthConfig
    rate_limiter: RateLimiter
    signup_hooks: dict[str, Callable[[Any, Request], Awaitable[Any]]]
    login_hooks: dict[str, Callable[[Any, Request], Awaitable[Any]]]
    logout_hooks: dict[str, Callable[[Any], Awaitable[None]]]
    refresh_hooks: dict[str, Callable[[Any, Request], Awaitable[None]]]
    password_hooks: dict[str, Callable[[Any, Request], Awaitable[None]]]
    password_hasher: PasswordHash
    refresh_model: type[Any] | None = None
    session_model: type[Any] | None = None
    password_reset_token_model: type[Any] | None = None

    def build_adapter(self, session: Any) -> Adapter:
        """Wrap the request's session. Sync: no I/O, cheap per-request bind."""
        return self.adapter_class(
            db_session=session,
            user_model=self.user_model,
            session_model=self.session_model,
            jwt_config=self.config.jwt,
            refresh_model=self.refresh_model,
            session_expire_days=self.config.session.expire_days,
            password_reset_token_model=self.password_reset_token_model,
            password_hasher=self.password_hasher,
        )


@dataclass
class OIDCContext:
    """Everything an OIDC route needs, built once in `OIDCAuth.__init__`.

    `adapter_class` is a *class*, not an instance — `build_adapter(session)`
    instantiates it per-request, bound to that request's DB session, same
    pattern AuthContext already uses.
    """

    adapter_class: type[Adapter]
    user_model: type[Any]
    oidc_account_model: type[Any]
    session_model: type[Any] | None
    refresh_model: type[Any] | None
    db_session_dependency: Callable[[], AsyncGenerator[Any]]
    strategy: Literal["session", "jwt"]
    config: FastAuthConfig
    state_manager: OIDCStateManager
    providers: dict[str, OIDCProvider]
    rate_limiter: RateLimiter
    login_hooks: dict[str, Callable[[Any, Request], Awaitable[Any]]]

    def build_adapter(self, session: Any) -> Adapter:
        """Instantiate the adapter bound to this request's DB session."""
        return self.adapter_class(
            db_session=session,
            user_model=self.user_model,
            session_model=self.session_model,
            jwt_config=self.config.jwt,
            refresh_model=self.refresh_model,
            session_expire_days=self.config.session.expire_days,
            oidc_account_model=self.oidc_account_model,
        )

    def get_provider(self, name: str) -> OIDCProvider:
        """Look up a registered provider by name, or raise a clear error."""
        try:
            return self.providers[name]
        except KeyError:
            msg = f"Unknown OIDC provider: {name!r}. Registered: {list(self.providers)}"
            raise KeyError(msg) from None
