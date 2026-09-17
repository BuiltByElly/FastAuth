"""FastAuth entrypoint: config + per-instance router."""

from collections.abc import AsyncGenerator, Callable
from enum import Enum
from typing import Literal

from fastapi import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import Adapter
from fastauth.config import JWTConfig
from fastauth.dependencies import jwt_current_user, session_current_user
from fastauth.models import (
    FastAuthRefreshTokenMixin,
    FastAuthSessionMixin,
    FastAuthUserMixin,
)
from fastauth.routes.context import AuthContext
from fastauth.routes.jwt_route import register_jwt_routes
from fastauth.routes.session import register_session_routes
from fastauth.schemas import build_signup_schema, build_user_response_schema


class FastAuth:
    """Configure auth once, mount `auth.router` on your app.

    Owns its own APIRouter (no shared/global state). Route modules
    per strategy (session/jwt) register onto it at startup.

    `auth.current_user` is a dependency resolving the request's user
    (session cookie for the session strategy, bearer token for JWT):
    use it as `Depends(auth.current_user)` in your own routes.
    """

    def __init__(
        self,
        adapter: type[Adapter],
        db_session_dependency: Callable[[], AsyncGenerator[AsyncSession]],
        user_model: type[FastAuthUserMixin],
        session_model: type[FastAuthSessionMixin] | None = None,
        refresh_model: type[FastAuthRefreshTokenMixin] | None = None,
        tags: list[str | Enum] | None = None,
        strategy: Literal["session", "jwt"] = "session",
        prefix: str = "/auth",
        jwt_config: JWTConfig | None = None,
    ):
        """Bind models + session provider; build schemas, router, routes.

        Args:
            adapter: Adapter class, built per request (session or JWT flavor).
            user_model: App's User model (uses FastAuthUserMixin).
            session_model: App's Session model (required for session, None for JWT).
            db_session_dependency: FastAPI dependency yielding an AsyncSession.
            tags: Optional list of tags for the router.
            strategy: Which route module to mount.
            prefix: Router prefix.
            jwt_config: Required when strategy="jwt". Validated settings the
                JWT adapter signs and validates tokens with.
            refresh_model: App's refresh-token model (required for JWT;
                enables single-use rotation + reuse detection).
        """
        if strategy == "session" and session_model is None:
            msg = "Session strategy requires a session_model."
            raise ValueError(msg)
        if strategy == "jwt" and jwt_config is None:
            msg = "JWT strategy requires a jwt_config."
            raise ValueError(msg)
        if strategy == "jwt" and refresh_model is None:
            msg = "JWT strategy requires a refresh_model."
            raise ValueError(msg)
        self.strategy = strategy
        self.jwt_config = jwt_config
        self.refresh_model = refresh_model

        self.signup_schema = build_signup_schema(adapter.get_extra_fields(user_model))
        self.user_response_schema = build_user_response_schema(
            adapter.get_response_fields(user_model)
        )

        self.ctx = AuthContext(
            adapter_class=adapter,
            user_model=user_model,
            session_model=session_model,
            db_session_dependency=db_session_dependency,
            signup_schema=self.signup_schema,
            user_response_schema=self.user_response_schema,
            strategy=strategy,
            jwt_config=jwt_config,
            refresh_model=refresh_model,
        )
        if strategy == "session":
            self.current_user = session_current_user(self.ctx)
        else:
            self.current_user = jwt_current_user(self.ctx)
        tags = tags or ["Authentication"]
        self.router = APIRouter(prefix=prefix, tags=tags)
        self._register_routes()

    def build_adapter(self, db_session: AsyncSession) -> Adapter:
        """Wrap the request's db session. Sync: no I/O, cheap per-request bind."""
        return self.ctx.build_adapter(db_session)

    def _register_routes(self) -> None:
        """Mount the strategy's routes. Sync: runs once at startup, no I/O."""
        if self.strategy == "session":
            register_session_routes(self.router, self.ctx, self.current_user)
        else:
            register_jwt_routes(self.router, self.ctx, self.current_user)
