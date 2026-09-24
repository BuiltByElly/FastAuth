"""Per-request database bridge for FastAuth."""

from abc import ABC, abstractmethod
from typing import Any

from pwdlib import PasswordHash

from fastauth.config import JWTConfig
from fastauth.protocols import RateLimitT, RefreshT, SessionT, UserT


class Adapter[UserT, SessionT](ABC):
    """Abstract base class for the JWT and Sessions strategy ORM adapters. Wraps one request-scoped session.

    Subclasses share method names; session vs JWT differ internally.
    Never commits — only adds/flushes. The caller (route) owns commit.

    Import and inherit from this class to create your own adapter for an ORM FastAuth does not support yet.
    Remember, it is an abstract base class — you must implement all abstract methods for only JWT or Sessions strategy.
    """

    def __init__(
        self,
        db_session: Any,
        user_model: type[UserT],
        session_model: type[SessionT] | None = None,
        jwt_config: JWTConfig | None = None,
        refresh_model: type[RefreshT] | None = None,
        session_expire_days: int = 7,
        password_hasher: PasswordHash | None = None,
    ):
        """Store the request-scoped session plus app models (no commit here).

        ``db_session`` is intentionally opaque: each backend defines what a
        "session" is (e.g. SQLAlchemy's ``AsyncSession``). It is only ever
        passed back into the backend's own adapter methods.
        """
        self.db_session = db_session
        self.user_model: type[UserT] = user_model
        self.session_model: type[SessionT] | None = session_model
        self.jwt_config = jwt_config
        self.refresh_model = refresh_model
        self.session_expire_days = session_expire_days
        self.password_hasher = password_hasher

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
    async def revoke_credential(self, token: str) -> str | None:
        """Invalidate a credential: delete row (session) or no-op (JWT)."""
        ...

    async def issue_refresh_token(self, user: UserT) -> str:
        """Mint + store a refresh token (JWT-only; others raise)."""
        raise NotImplementedError("This strategy does not support refresh tokens.")

    async def consume_refresh_token(self, token: str) -> UserT | None:
        """Validate a refresh token single-use (burn it) -> user or None.

        Returns True if the token was consumed and its family revoked, or None if invalid/expired.
        """
        raise NotImplementedError("This strategy does not support refresh tokens.")

    async def revoke_refresh_token(self, token: str) -> str | None:
        """Delete a refresh token row if present and return the user's id for on_after_logout hook; never raises."""
        raise NotImplementedError("This strategy does not support refresh tokens.")

    async def purge_expired_refresh_tokens(self) -> int:
        """Delete expired refresh-token rows; returns the deleted count.

        Expired rows are useless even for reuse detection (their JWTs fail
        the `exp` check before the row is ever read). Flushes; the caller
        commits. Designed for a scheduler job.
        """
        raise NotImplementedError("This strategy does not support refresh tokens.")


class RateLimiterAdapter[RateLimitT](ABC):
    def __init__(self, db_session: Any, model: type[RateLimitT]):
        self.db_session = db_session
        self.model = model

    @abstractmethod
    async def check(self, key: str, window: int, max_requests: int) -> bool:
        """True if allowed (and increments count), False if over limit."""
        ...
