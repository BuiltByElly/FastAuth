"""Per-request database bridge for FastAuth."""

from abc import ABC, abstractmethod
from typing import Any

from pwdlib import PasswordHash

from fastauth.config import JWTConfig
from fastauth.protocols import (
    OAuthAccountT,
    PasswordResetTokenT,
    RefreshT,
    SessionT,
    UserT,
)
from fastauth.types import OAuthUserInfo


class Adapter[UserT, SessionT, OAuthAccountT](ABC):
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
        password_reset_token_model: type[PasswordResetTokenT] | None = None,
        oauth_account_model: type[OAuthAccountT] | None = None,
    ):
        """Store the request-scoped session plus app models (no commit here).

        ``db_session`` is intentionally opaque: each backend defines what a
        "session" is (e.g. SQLAlchemy's ``AsyncSession``). It is only ever
        passed back into the backend's own adapter methods.
        """
        self.db_session = db_session
        self.user_model = user_model
        self.session_model = session_model
        self.jwt_config = jwt_config
        self.refresh_model = refresh_model
        self.session_expire_days = session_expire_days
        self.password_hasher = password_hasher
        self.password_reset_token_model = password_reset_token_model
        self.oauth_account_model = oauth_account_model

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

    @abstractmethod
    def require_password_reset_model(
        self,
    ) -> type[PasswordResetTokenT]: ...

    @abstractmethod
    def require_oauth_account_model(
        self,
    ) -> type[OAuthAccountT]: ...

    @abstractmethod
    async def get_oidc_account(
        self, provider: str, provider_user_id: str
    ) -> OAuthAccountT: ...

    @abstractmethod
    async def create_user_from_oidc(self, user_info: OAuthUserInfo) -> UserT: ...

    @abstractmethod
    async def get_oauth2_account(
        self, provider: str, provider_user_id: str
    ) -> OAuthAccountT: ...

    @abstractmethod
    async def create_user_from_oauth2(self, user_info: OAuthUserInfo) -> UserT: ...

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

    async def set_password(self, user: UserT, new_password: str) -> None:
        """Hash and persist a new password for the user."""

    async def revoke_credentials_on_password_reset(self, user: UserT) -> None:
        """Invalidate whatever currently lets this user stay logged in.

        Session strategy: delete/revoke session rows.
        JWT strategy: stamp `password_changed_at` and revoke the refresh
        token family, so old access tokens are rejected and no new ones
        can be minted from a stolen refresh token.
        """

    async def create_password_reset_token(self, user: UserT) -> str: ...

    async def consume_password_reset_token(self, token: str) -> UserT | None: ...


class RateLimiterAdapter[RateLimitT](ABC):
    @abstractmethod
    async def check(self, key: str, window: int, max_requests: int) -> bool:
        """True if allowed (and increments count), False if over limit."""
        ...
