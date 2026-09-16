"""SQLAlchemy adapters: session vs JWT, same interface, different internals."""

import secrets
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import inspect, select
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import Adapters
from fastauth.models import FastAuthSessionMixin, FastAuthUserMixin
from fastauth.security import hash_password

SESSION_EXPIRE_DAYS = 7


def _tagged_fields(model: type, flag: str) -> dict[str, tuple[type, Any]]:
    """Columns the dev opted in via fastauth info flags. Untagged skipped."""
    fields = {}
    for col in inspect(model).columns:
        if not col.info.get(flag, False):
            continue
        fields[col.key] = (col.type.python_type, ... if not col.nullable else None)
    return fields


class SQLAlchemySessionAdapter(Adapters):
    """DB-backed credentials: sessions persisted as rows, expiry enforced."""

    def __init__(
        self,
        db_session: AsyncSession,
        user_model: type[FastAuthUserMixin],
        session_model: type[FastAuthSessionMixin],
    ):
        """Bind a request session plus the app's User/Session models."""
        super().__init__(db_session, user_model, session_model)

    @classmethod
    def get_extra_fields(cls, model: type) -> dict[str, tuple[type, Any]]:
        """Columns tagged fastauth_input=True."""
        return _tagged_fields(model, "fastauth_input")

    @classmethod
    def get_response_fields(cls, model: type) -> dict[str, tuple[type, Any]]:
        """Columns tagged fastauth_returned=True."""
        return _tagged_fields(model, "fastauth_returned")

    async def get_user_by_email(self, email: str) -> Any | None:
        """Find a user by email, or None."""
        res = await self.db_session.execute(
            select(self.user_model).where(self.user_model.email == email)  # type: ignore[attr-defined]
        )
        return res.scalar_one_or_none()

    async def get_user_by_id(self, user_id: Any) -> Any | None:
        """Find a user by id, or None."""
        return await self.db_session.get(self.user_model, user_id)

    async def create_user(self, data: dict[str, Any]) -> Any:
        """Create a user; plain 'password' is hashed to hashed_password."""
        data = dict(data)
        password = data.pop("password")
        user = self.user_model(
            email=data.pop("email"),  # type: ignore[call-arg]
            hashed_password=hash_password(password),  # type: ignore[call-arg]
            **data,
        )
        self.db_session.add(user)
        await self.db_session.flush()
        return user

    async def issue_credential(self, user: Any) -> Any:
        """Create a session row valid for SESSION_EXPIRE_DAYS."""
        now = datetime.now(UTC)
        session = self.session_model(  # type: ignore[call-arg]
            user_id=user.id,  # type: ignore[call-arg]
            created_at=now,  # type: ignore[call-arg]
            expires_at=now + timedelta(days=SESSION_EXPIRE_DAYS),  # type: ignore[call-arg]
        )
        self.db_session.add(session)
        await self.db_session.flush()
        return session

    async def resolve_credential(self, token: str) -> Any | None:
        """Session id -> user, or None if missing/expired."""
        try:
            session_id = uuid.UUID(token)
        except ValueError:
            return None
        session = await self.db_session.get(self.session_model, session_id)  # type: ignore[call-arg]
        if session is None:
            return None
        expires = session.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires <= datetime.now(UTC):
            return None
        return await self.db_session.get(self.user_model, session.user_id)

    async def revoke_credential(self, token: str) -> None:
        """Delete the session row; unknown ids are ignored."""
        try:
            session_id = uuid.UUID(token)
        except ValueError:
            return
        session = await self.db_session.get(self.session_model, session_id)  # type: ignore[call-arg]
        if session is not None:
            await self.db_session.delete(session)
            await self.db_session.flush()


class SQLAlchemyJWTAdapter(Adapters):
    """Stateless credentials: placeholder signed tokens, no session rows.

    Token scheme is a stand-in until real JWT signing lands (see routes/jwt).
    """

    def __init__(
        self,
        db_session: AsyncSession,
        user_model: type[FastAuthUserMixin],
        session_model: type[FastAuthSessionMixin] | None = None,
    ):
        """Bind a request session plus the app's User model (no sessions)."""
        super().__init__(db_session, user_model, session_model)

    @classmethod
    def get_extra_fields(cls, model: type) -> dict[str, tuple[type, Any]]:
        """Columns tagged fastauth_input=True."""
        return _tagged_fields(model, "fastauth_input")

    @classmethod
    def get_response_fields(cls, model: type) -> dict[str, tuple[type, Any]]:
        """Columns tagged fastauth_returned=True."""
        return _tagged_fields(model, "fastauth_returned")

    async def get_user_by_email(self, email: str) -> Any | None:
        """Find a user by email, or None."""
        res = await self.db_session.execute(
            select(self.user_model).where(self.user_model.email == email)  # type: ignore[attr-defined]
        )
        return res.scalar_one_or_none()

    async def get_user_by_id(self, user_id: Any) -> Any | None:
        """Find a user by id, or None."""
        return await self.db_session.get(self.user_model, user_id)

    async def create_user(self, data: dict[str, Any]) -> Any:
        """Create a user; plain 'password' is hashed to hashed_password."""
        data = dict(data)
        password = data.pop("password")
        user = self.user_model(
            email=data.pop("email"),  # type: ignore[call-arg]
            hashed_password=hash_password(password),  # type: ignore[call-arg]
            **data,
        )
        self.db_session.add(user)
        await self.db_session.flush()
        return user

    async def issue_credential(self, user: Any) -> str:
        """Mint a placeholder token encoding the user id (see routes/jwt)."""
        return f"fastauth.{user.id}.{secrets.token_urlsafe(24)}"

    async def resolve_credential(self, token: str) -> Any | None:
        """Placeholder token -> user, or None if malformed/unknown."""
        try:
            _, user_id, _ = token.split(".", 2)
            return await self.get_user_by_id(uuid.UUID(user_id))
        except ValueError, AttributeError:
            return None

    async def revoke_credential(self, token: str) -> None:
        """No-op: stateless tokens can't be revoked server-side (placeholder)."""
