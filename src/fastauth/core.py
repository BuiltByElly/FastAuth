"""FastAuth entrypoint: config + per-instance router."""

from collections.abc import AsyncGenerator, Callable
from typing import Literal

from fastapi import APIRouter
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import Adapters
from fastauth.models import FastAuthSessionMixin, FastAuthUserMixin
from fastauth.routes.context import AuthContext
from fastauth.routes.jwt import register_jwt_routes
from fastauth.routes.session import register_session_routes
from fastauth.schemas import build_signup_schema, build_user_response_schema


class FastAuth:
    """Configure auth once, mount `auth.router` on your app.

    Owns its own APIRouter (no shared/global state). Route modules
    per strategy (session/jwt) register onto it at startup.
    """

    def __init__(
        self,
        adapter: type[Adapters],
        user_model: type[FastAuthUserMixin],
        session_model: type[FastAuthSessionMixin] | None,
        db_session_dependency: Callable[[], AsyncGenerator[AsyncSession]],
        strategy: Literal["session", "jwt"] = "session",
        prefix: str = "/auth",
    ):
        """Bind models + session provider; build schemas, router, routes.

        Args:
            adapter: Adapter class, built per request (session or JWT flavor).
            user_model: App's User model (uses FastAuthUserMixin).
            session_model: App's Session model (required for session, None for JWT).
            db_session_dependency: FastAPI dependency yielding an AsyncSession.
            strategy: Which route module to mount.
            prefix: Router prefix.
        """
        if strategy == "session" and session_model is None:
            msg = "Session strategy requires a session_model."
            raise ValueError(msg)
        self.strategy = strategy

        self.signup_schema = build_signup_schema(
            adapter.get_extra_fields(user_model)
        )
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
        )
        self.router = APIRouter(prefix=prefix)
        self._register_routes()

    def build_adapter(self, session: AsyncSession) -> Adapters:
        """Wrap the request's session. Sync: no I/O, cheap per-request bind."""
        return self.ctx.build_adapter(session)

    def _register_routes(self) -> None:
        """Mount the strategy's routes. Sync: runs once at startup, no I/O."""
        if self.strategy == "session":
            register_session_routes(self.router, self.ctx)
        else:
            register_jwt_routes(self.router, self.ctx)
