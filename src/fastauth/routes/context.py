"""Shared route context: what strategy modules need from FastAuth."""

from collections.abc import AsyncGenerator, Callable
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import Adapters
from fastauth.models import FastAuthSessionMixin, FastAuthUserMixin


@dataclass
class AuthContext:
    """Per-instance state passed to route registrars (avoids core cycles)."""

    adapter_class: type[Adapters]
    user_model: type[FastAuthUserMixin]
    session_model: type[FastAuthSessionMixin] | None
    db_session_dependency: Callable[[], AsyncGenerator[AsyncSession]]
    signup_schema: type[BaseModel]
    user_response_schema: type[BaseModel]
    strategy: Literal["session", "jwt"]

    def build_adapter(self, session: AsyncSession) -> Adapters:
        """Wrap the request's session. Sync: no I/O, cheap per-request bind."""
        return self.adapter_class(
            db_session=session,
            user_model=self.user_model,
            session_model=self.session_model,  # type: ignore[arg-type]
        )


def bearer_token(authorization: str | None) -> str | None:
    """Extract the token from a 'Bearer <token>' header, or None."""
    if not authorization or not authorization.startswith("Bearer "):
        return None
    return authorization[len("Bearer ") :]
