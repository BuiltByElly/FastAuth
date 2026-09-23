"""FastAuth entrypoints: one auth class per strategy, shared base.

`SessionAuth` and `JWTAuth` own their models, routes, and `current_user`
dependency — no `strategy` flag, no `if/else` branching. Common setup
(config, schemas, router, adapter binding) lives on the `FastAuth` base.
Rate limiting is a separate component, see `fastauth.dependencies.rate_limiter`.
"""

import warnings
from collections.abc import AsyncGenerator, Callable
from datetime import UTC, datetime
from enum import Enum
from typing import Literal

from fastapi import APIRouter
from sqlalchemy import delete, or_
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import Adapter
from fastauth.dependencies.current_user import jwt_current_user, session_current_user
from fastauth.dependencies.rate_limiter import RateLimiter
from fastauth.hooks.login import LoginHooks
from fastauth.hooks.logout import LogoutHooks
from fastauth.hooks.refresh import RefreshHooks
from fastauth.hooks.signup import SignupHooks
from fastauth.models import (
    FastAuthRefreshTokenMixin,
    FastAuthSessionMixin,
    FastAuthUserMixin,
)
from fastauth.routes.context import AuthContext
from fastauth.routes.jwt_route import register_jwt_routes
from fastauth.routes.session import register_session_routes
from fastauth.schemas import (
    build_login_schema,
    build_signup_schema,
    build_user_response_schema,
)
from fastauth.security import build_hasher

from .config import FastAuthConfig, RateLimitConfig


class FastAuth:
    """Shared base: config, schemas, router, and per-request adapter binding.

    Not usable on its own (registers no routes, sets no `current_user`) —
    use `SessionAuth` or `JWTAuth`. Owns its own APIRouter, so instances
    never share state.
    """

    strategy: Literal["session", "jwt"]

    def __init__(
        self,
        adapter: type[Adapter],
        db_session_dependency: Callable[[], AsyncGenerator[AsyncSession]],
        user_model: type[FastAuthUserMixin],
        rate_limiter: RateLimiter | None = None,
        tags: list[str | Enum] | None = None,
        prefix: str = "/auth",
        config: FastAuthConfig | None = None,
    ):
        """Bind shared setup; subclasses mount their routes.

        Args:
            adapter: Per-request DB bridge (session or JWT flavor).
            db_session_dependency: FastAPI dep yielding an AsyncSession.
            user_model: App User (uses FastAuthUserMixin).
            rate_limiter: Ready-made limiter instance. When passed it owns
                ALL rate-limit behavior and `config.rate_limit` is ignored
                (a warning is emitted if that section is non-default).
                When omitted, one is built from `config.rate_limit`.
            tags: Router tags. prefix: Router prefix.
            config: Single config object; defaults to `FastAuthConfig()`.
        """
        cfg = config or FastAuthConfig()
        self.config = cfg
        self.password_hasher = build_hasher(cfg.password.hash_schemes)
        if rate_limiter is not None and cfg.rate_limit != RateLimitConfig():
            warnings.warn(
                "A rate_limiter instance was passed explicitly, so the "
                "config.rate_limit section is ignored. Configure the "
                "RateLimiter directly instead.",
                UserWarning,
                stacklevel=3,
            )
        self.rate_limiter = rate_limiter or RateLimiter(
            rate_limit_config=cfg.rate_limit
        )

        self.signup_schema = build_signup_schema(
            adapter.get_extra_fields(user_model),
            password_config=cfg.password,
        )
        self.login_schema = build_login_schema(password_config=cfg.password)
        self.user_response_schema = build_user_response_schema(
            adapter.get_response_fields(user_model)
        )

        self.signup_hooks = SignupHooks(
            schema=self.signup_schema,
        )
        self.on_before_signup = self.signup_hooks.on_before_signup
        self.on_after_signup = self.signup_hooks.on_after_signup
        self.on_signup_failure = self.signup_hooks.on_signup_failure

        self.login_hooks = LoginHooks(
            schema=self.login_schema,
        )
        self.on_before_login = self.login_hooks.on_before_login
        self.on_login_failure = self.login_hooks.on_login_failure
        self.on_after_login = self.login_hooks.on_after_login

        self.logout_hooks = LogoutHooks()
        self.on_after_logout = self.logout_hooks.add_after_logout

        self.refresh_hooks = RefreshHooks()
        self.on_token_reuse_detected = self.refresh_hooks.on_token_reuse_detected

        self.ctx = AuthContext(
            adapter_class=adapter,
            user_model=user_model,
            session_model=None,
            db_session_dependency=db_session_dependency,
            signup_schema=self.signup_schema,
            login_schema=self.login_schema,
            user_response_schema=self.user_response_schema,
            strategy=self.strategy,
            config=cfg,
            password_hasher=self.password_hasher,
            refresh_model=None,
            rate_limiter=self.rate_limiter,
            signup_hooks={
                "run_before_signup": self.signup_hooks.run_before_signup,
                "run_after_signup": self.signup_hooks.run_after_signup,
                "run_signup_failure": self.signup_hooks.run_signup_failure,
            },
            login_hooks={
                "run_before_login": self.login_hooks.run_before_login,
                "run_login_failure": self.login_hooks.run_login_failure,
                "run_after_login": self.login_hooks.run_after_login,
            },
            logout_hooks={
                "run_after_logout": self.logout_hooks.run_after_logout,
            },
            refresh_hooks={
                "run_token_reuse_detected": self.refresh_hooks.run_token_reuse_detected,
            },
        )
        tags = tags or ["Authentication"]
        self.router = APIRouter(prefix=prefix, tags=tags)


class SessionAuth(FastAuth):
    """DB-backed session auth (cookie transport, server-side rows).

    `auth.current_user` resolves the user from the session cookie:
    use it as `Depends(auth.current_user)` in your own routes.
    """

    strategy = "session"

    def __init__(
        self,
        adapter: type[Adapter],
        db_session_dependency: Callable[[], AsyncGenerator[AsyncSession]],
        user_model: type[FastAuthUserMixin],
        session_model: type[FastAuthSessionMixin],
        rate_limiter: RateLimiter | None = None,
        tags: list[str | Enum] | None = None,
        prefix: str = "/auth",
        config: FastAuthConfig | None = None,
    ):
        """Bind models + session provider; mount signup/login/logout/me.

        Args:
            rate_limiter: Ready-made limiter (owns behavior; `config.rate_limit`
                is then ignored). Omit to build one from `config.rate_limit`.
        """
        super().__init__(
            adapter=adapter,
            db_session_dependency=db_session_dependency,
            user_model=user_model,
            rate_limiter=rate_limiter,
            tags=tags,
            prefix=prefix,
            config=config,
        )

        self.current_user = session_current_user(self.ctx)
        self.ctx.session_model = session_model
        register_session_routes(self.router, self.ctx, self.current_user)


class JWTAuth(FastAuth):
    """Stateless JWT access tokens + rotating refresh cookies.

    `auth.current_user` resolves the user from the bearer access token:
    use it as `Depends(auth.current_user)` in your own routes.
    """

    strategy = "jwt"

    def __init__(
        self,
        adapter: type[Adapter],
        db_session_dependency: Callable[[], AsyncGenerator[AsyncSession]],
        user_model: type[FastAuthUserMixin],
        refresh_model: type[FastAuthRefreshTokenMixin],
        rate_limiter: RateLimiter | None = None,
        tags: list[str | Enum] | None = None,
        prefix: str = "/auth",
        config: FastAuthConfig | None = None,
    ):
        """Bind models + session provider; mount signup/login/refresh/logout/me.

        Args:
            refresh_model: App refresh-token model (single-use rotation).
            rate_limiter: Ready-made limiter (owns behavior; `config.rate_limit`
                is then ignored). Omit to build one from `config.rate_limit`.
            config: Must include `jwt` (secret, algorithm, lifetimes).
        """
        super().__init__(
            adapter=adapter,
            db_session_dependency=db_session_dependency,
            user_model=user_model,
            rate_limiter=rate_limiter,
            tags=tags,
            prefix=prefix,
            config=config,
        )
        if self.config.jwt is None:
            msg = "JWTAuth requires config.jwt (pass FastAuthConfig with jwt=JWTConfig(...))."
            raise ValueError(msg)
        self.refresh_model = refresh_model
        self.ctx.refresh_model = refresh_model
        self.current_user = jwt_current_user(self.ctx)
        register_jwt_routes(self.router, self.ctx, self.current_user)

    async def purge_expired_refresh_tokens(self, session: AsyncSession) -> int:
        """Delete expired refresh-token rows; returns the deleted count.

        Expired rows are useless even for reuse detection (their JWTs fail
        the `exp` check before the row is ever read), so this only removes
        garbage. Outstanding and consumed-but-unexpired rows are kept.

        Flushes; the caller commits. Designed for a scheduler job, e.g.::

            async def purge_job() -> None:
                async with session_factory() as session:
                    deleted = await auth.purge_expired_refresh_tokens(session)
                    await session.commit()
                    logger.info("purged %d refresh tokens", deleted)
        """
        result = await session.execute(
            delete(self.refresh_model).where(
                or_(
                    self.refresh_model.expires_at.is_(None),  # type: ignore[attr-defined]
                    self.refresh_model.expires_at <= datetime.now(UTC),  # type: ignore[attr-defined]
                )
            )
        )
        await session.flush()
        return result.rowcount  # type: ignore[attr-defined]
