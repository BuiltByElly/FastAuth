"""SQLAlchemy adapters: session vs JWT, same interface, different internals."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from pwdlib import PasswordHash
from sqlalchemy import inspect, select
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import Adapter, SessionT, UserT
from fastauth.config import JWTConfig
from fastauth.security import hash_password

from .models import FastAuthRefreshTokenMixin


def _tagged_fields(model: type, flag: str) -> dict[str, tuple[type, Any]]:
    """Columns the dev opted in via fastauth info flags. Untagged skipped."""
    fields = {}
    for col in inspect(model).columns:
        if not col.info.get(flag, False):
            continue
        fields[col.key] = (col.type.python_type, ... if not col.nullable else None)
    return fields


class SQLAlchemySessionAdapter(Adapter[UserT, SessionT]):
    """DB-backed credentials: sessions persisted as rows, expiry enforced."""

    def __init__(
        self,
        db_session: AsyncSession,
        user_model: type[UserT],
        session_model: type[SessionT],
        jwt_config: JWTConfig | None = None,
        refresh_model: type[FastAuthRefreshTokenMixin] | None = None,
        session_expire_days: int = 7,
        password_hasher: PasswordHash | None = None,
    ):
        """Bind a request session plus the app's User/Session models."""
        super().__init__(
            db_session,
            user_model,
            session_model,
            jwt_config,
            refresh_model,
            session_expire_days,
            password_hasher,
        )

    @classmethod
    def get_extra_fields(cls, model: type) -> dict[str, tuple[type, Any]]:
        """Columns tagged fastauth_input=True."""
        return _tagged_fields(model, "fastauth_input")

    @classmethod
    def get_response_fields(cls, model: type) -> dict[str, tuple[type, Any]]:
        """Columns tagged fastauth_returned=True."""
        return _tagged_fields(model, "fastauth_returned")

    async def get_user_by_email(self, email: str) -> UserT | None:
        """Find a user by email, or None."""
        res = await self.db_session.execute(
            select(self.user_model).where(self.user_model.email == email)  # type: ignore[attr-defined]
        )
        return res.scalar_one_or_none()

    async def get_user_by_id(self, user_id: Any) -> UserT | None:
        """Find a user by id, or None."""
        return await self.db_session.get(self.user_model, user_id)

    async def create_user(self, data: dict[str, Any]) -> UserT:
        """Create a user; plain 'password' is hashed to hashed_password."""
        data = dict(data)
        password = data.pop("password")
        user = self.user_model(
            email=data.pop("email"),  # type: ignore[call-arg]
            hashed_password=hash_password(password, self.password_hasher),  # type: ignore[call-arg]
            **data,
        )
        self.db_session.add(user)
        await self.db_session.flush()
        return user

    async def issue_credential(self, user: UserT) -> SessionT:
        """Create a session row valid for `session_expire_days`."""
        now = datetime.now(UTC)
        session = self.session_model(  # type: ignore[call-arg]
            user_id=user.id,  # type: ignore[call-arg]
            created_at=now,  # type: ignore[call-arg]
            expires_at=now + timedelta(days=self.session_expire_days),  # type: ignore[call-arg]
        )
        self.db_session.add(session)
        await self.db_session.flush()
        return session

    async def resolve_credential(self, token: str) -> UserT | None:
        """Session id -> user, or None if missing/expired/inactive."""
        try:
            session_id = uuid.UUID(token)
        except ValueError, AttributeError, TypeError:
            return None
        session: Any = await self.db_session.get(self.session_model, session_id)  # type: ignore[call-arg]
        if session is None:
            return None
        expires = session.expires_at
        if expires is None:
            return None
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires <= datetime.now(UTC):
            return None
        user = await self.db_session.get(self.user_model, session.user_id)
        if user is None or not user.is_active:
            return None
        return user

    async def revoke_credential(self, token: str) -> str | None:
        """Delete the session row; unknown ids are ignored."""
        try:
            session_id = uuid.UUID(token)
        except ValueError, AttributeError, TypeError:
            return
        session = await self.db_session.get(self.session_model, session_id)  # type: ignore[call-arg]
        if session is not None:
            user_id = str(session.user_id)  # type:ignore
            await self.db_session.delete(session)
            await self.db_session.flush()
            return user_id  # type:ignore
