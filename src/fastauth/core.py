"""FastAuth entrypoint: config + per-instance router."""

from collections.abc import AsyncGenerator, Callable
from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import Adapters
from fastauth.models import FastAuthSessionMixin, FastAuthUserMixin


class FastAuth:
    """Configure auth once, mount `auth.router` on your app.

    Owns its own APIRouter (no shared/global state). Routes are
    registered in `_register_routes` — add new ones there so they
    always show up in OpenAPI.
    """

    def __init__(
        self,
        adapter: type[Adapters],
        user_model: type[FastAuthUserMixin],
        session_model: type[FastAuthSessionMixin],
        db_session_dependency: Callable[[], AsyncGenerator[AsyncSession]],
        strategy: Literal["session", "jwt"] = "session",
        prefix: str = "/auth",
    ):
        """Bind models + session provider; build router and routes.

        Args:
            adapter: Adapter class (e.g. SQLAlchemyAdapter), built per request.
            user_model: App's User model (uses FastAuthUserMixin).
            session_model: App's Session model (uses FastAuthSessionMixin).
            db_session: FastAPI dependency yielding an AsyncSession.
            strategy: Auth strategy name.
            prefix: Router prefix.
        """
        self.adapter_class = adapter
        self.user_model = user_model
        self.session_model = session_model
        self.db_session_dependency = db_session_dependency
        self.strategy = strategy
        self.router = APIRouter(prefix=prefix)
        self._register_routes()

    def build_adapter(self, db_session: AsyncSession) -> Adapters:
        """Wrap the request's session in an adapter.

        Per-request because AsyncSession is single-request state (transaction
        + identity map) and must not be shared across requests. Cheap to
        construct; the shared engine/pool underneath is what scales.
        """
        return self.adapter_class(
            db_session=db_session,
            user_model=self.user_model,
            session_model=self.session_model,
        )

    def _register_routes(self) -> None:
        """Declare all auth routes. Sync: runs once at startup, no I/O.

        Handlers defined inside stay `async` — that's where DB awaits happen.
        """

        @self.router.post("/signup")
        async def signup(
            db_session: Annotated[AsyncSession, Depends(self.db_session_dependency)],
        ):
            """Placeholder signup. DB logic comes next."""
            _ = self.build_adapter(db_session)
            return {"message": "signup"}
