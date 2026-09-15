"""Per-request database bridge for FastAuth."""

from abc import ABC, abstractmethod
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.models import FastAuthSessionMixin, FastAuthUserMixin


class Adapters(ABC):
    """Base adapter. Wraps one request-scoped session.

    Subclasses share method names; session vs JWT differ internally.
    Never commits — only adds/flushes. The caller (route) owns commit.
    """

    def __init__(
        self,
        db_session: AsyncSession,
        user_model: type[FastAuthUserMixin],
        session_model: type[FastAuthSessionMixin] | None = None,
    ):
        """Store the request-scoped session plus app models (no commit here)."""
        self.db_session = db_session
        self.user_model = user_model
        self.session_model = session_model

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
    async def get_user_by_email(self, email: str) -> Any | None:
        """Find a user by email, or None."""
        ...

    @abstractmethod
    async def get_user_by_id(self, user_id: Any) -> Any | None:
        """Find a user by id, or None."""
        ...

    @abstractmethod
    async def create_user(self, data: dict[str, Any]) -> Any:
        """Create a user from signup data (plain password hashed inside)."""
        ...

    @abstractmethod
    async def issue_credential(self, user: Any) -> Any:
        """Issue a credential: session row (session) or token string (JWT)."""
        ...

    @abstractmethod
    async def resolve_credential(self, token: str) -> Any | None:
        """Token -> user, or None if invalid/expired."""
        ...

    @abstractmethod
    async def revoke_credential(self, token: str) -> None:
        """Invalidate a credential: delete row (session) or no-op (JWT)."""
        ...
