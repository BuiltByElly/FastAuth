"""Per-request database bridge for FastAuth."""

from abc import ABC, abstractmethod
from typing import Any, Generic, TypeVar

from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.config import JWTConfig
from fastauth.models import (
    FastAuthRefreshTokenMixin,
    FastAuthSessionMixin,
    FastAuthUserMixin,
)

UserT = TypeVar("UserT", bound=FastAuthUserMixin)
SessionT = TypeVar("SessionT", bound=FastAuthSessionMixin)


class Adapter(ABC, Generic[UserT, SessionT]):
    """Base adapter. Wraps one request-scoped session.

    Subclasses share method names; session vs JWT differ internally.
    Never commits — only adds/flushes. The caller (route) owns commit.
    """

    def __init__(
        self,
        db_session: AsyncSession,
        user_model: type[UserT],
        session_model: type[SessionT] | None = None,
        jwt_config: JWTConfig | None = None,
        refresh_model: type[FastAuthRefreshTokenMixin] | None = None,
    ):
        """Store the request-scoped session plus app models (no commit here)."""
        self.db_session = db_session
        self.user_model: type[UserT] = user_model
        self.session_model: type[SessionT] | None = session_model
        self.jwt_config = jwt_config
        self.refresh_model = refresh_model

    @classmethod
    @abstractmethod
    def get_extra_fields(cls, model: type) -> dict[str, tuple[type, Any]]:
        """Dev columns tagged fastauth_input=True (for signup schema)."""
        ...

    @classmethod
    @abstractmethod
    def get_response_fields(cls, model: type) -> dict[str, tuple[type, Any]]:
        """Dev columns tagged fastauth_returned=True (for response schema)."""
        ...

    @abstractmethod
    async def get_user_by_email(self, email: str) -> UserT | None:
        """Find a user by email, or None."""
        ...

    @abstractmethod
    async def get_user_by_id(self, user_id: Any) -> UserT | None:
        """Find a user by id, or None."""
        ...

    @abstractmethod
    async def create_user(self, data: dict[str, Any]) -> UserT:
        """Create a user from signup data (plain password hashed inside)."""
        ...

    @abstractmethod
    async def issue_credential(self, user: UserT) -> SessionT | str:
        """Issue a credential: session row (session) or token string (JWT)."""
        ...

    @abstractmethod
    async def resolve_credential(self, token: str) -> UserT | None:
        """Token -> user, or None if invalid/expired."""
        ...

    @abstractmethod
    async def revoke_credential(self, token: str) -> None:
        """Invalidate a credential: delete row (session) or no-op (JWT)."""
        ...

    async def issue_refresh_token(self, user: UserT) -> str:
        """Mint + store a refresh token (JWT-only; others raise)."""
        raise NotImplementedError("This strategy does not support refresh tokens.")

    async def consume_refresh_token(self, token: str) -> UserT | None:
        """Validate a refresh token single-use (burn it) -> user or None."""
        raise NotImplementedError("This strategy does not support refresh tokens.")

    async def revoke_refresh_token(self, token: str) -> None:
        """Delete a refresh token row if present; never raises."""
        raise NotImplementedError("This strategy does not support refresh tokens.")
