"""Shared route context: what strategy modules need from FastAuth."""

from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import Adapter
from fastauth.config import JWTConfig
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
    user_response_schema: type[BaseModel]
    strategy: Literal["session", "jwt"]
    jwt_config: JWTConfig | None = None
    refresh_model: type[FastAuthRefreshTokenMixin] | None = None

    def build_adapter(self, session: AsyncSession) -> Adapter:
        """Wrap the request's session. Sync: no I/O, cheap per-request bind."""
        return self.adapter_class(
            db_session=session,
            user_model=self.user_model,
            session_model=self.session_model,  # type: ignore[arg-type]
            jwt_config=self.jwt_config,
            refresh_model=self.refresh_model,
        )
