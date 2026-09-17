"""SQLAlchemy adapters: session vs JWT, same interface, different internals."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from sqlalchemy import delete, inspect, select
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import Adapter, SessionT, UserT
from fastauth.config import JWTConfig
from fastauth.models import FastAuthRefreshTokenMixin
from fastauth.security import hash_password

SESSION_EXPIRE_DAYS = 7

ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_TYPE = "refresh"


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
    ):
        """Bind a request session plus the app's User/Session models."""
        super().__init__(
            db_session, user_model, session_model, jwt_config, refresh_model
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
            hashed_password=hash_password(password),  # type: ignore[call-arg]
            **data,
        )
        self.db_session.add(user)
        await self.db_session.flush()
        return user

    async def issue_credential(self, user: UserT) -> SessionT:
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

    async def revoke_credential(self, token: str) -> None:
        """Delete the session row; unknown ids are ignored."""
        try:
            session_id = uuid.UUID(token)
        except ValueError, AttributeError, TypeError:
            return
        session = await self.db_session.get(self.session_model, session_id)  # type: ignore[call-arg]
        if session is not None:
            await self.db_session.delete(session)
            await self.db_session.flush()


class SQLAlchemyJWTAdapter(Adapter[UserT, SessionT]):
    """Stateless credentials: signed JWT access tokens, no session rows.

    Tokens carry ``sub`` (user id), ``exp``/``iat``, a ``jti``, and a
    ``type`` claim (``"access"`` here; ``"refresh"`` arrives with task 7).
    ``resolve_credential`` only accepts access tokens signed with the
    configured secret/algorithm — refresh tokens are rejected there.
    """

    def __init__(
        self,
        db_session: AsyncSession,
        user_model: type[UserT],
        session_model: type[SessionT] | None = None,
        jwt_config: JWTConfig | None = None,
        refresh_model: type[FastAuthRefreshTokenMixin] | None = None,
    ):
        """Bind a request session plus the app's User model (no sessions)."""
        super().__init__(
            db_session, user_model, session_model, jwt_config, refresh_model
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
            hashed_password=hash_password(password),  # type: ignore[call-arg]
            **data,
        )
        self.db_session.add(user)
        await self.db_session.flush()
        return user

    def _require_config(self) -> JWTConfig:
        """Return jwt_config or fail fast when the adapter is miswired."""
        if self.jwt_config is None:
            msg = "SQLAlchemyJWTAdapter requires jwt_config (pass JWTConfig via FastAuth)."
            raise ValueError(msg)
        return self.jwt_config

    def _encode(self, user: UserT, token_type: str, expires_delta: timedelta) -> str:
        """Sign one token with sub/exp/iat/jti/type claims."""
        cfg = self._require_config()
        now = datetime.now(UTC)
        payload = {
            "sub": str(user.id),
            "exp": now + expires_delta,
            "iat": now,
            "jti": uuid.uuid4().hex,
            "type": token_type,
        }
        return jwt.encode(payload, cfg.secret_key, algorithm=cfg.algorithm)

    def _decode(self, token: str, expected_type: str) -> dict[str, Any] | None:
        """Verify signature/expiry and token type. None if anything fails."""
        cfg = self._require_config()
        try:
            payload = jwt.decode(
                token,
                cfg.secret_key,
                algorithms=[cfg.algorithm],
                options={"require": ["exp", "sub"]},
            )
        except jwt.InvalidTokenError, ValueError, AttributeError, TypeError:
            return None
        if payload.get("type") != expected_type:
            return None
        return payload

    async def issue_credential(self, user: UserT) -> str:
        """Mint a signed access token expiring per ``jwt_config``."""
        cfg = self._require_config()
        return self._encode(
            user,
            ACCESS_TOKEN_TYPE,
            timedelta(minutes=cfg.access_token_expire_minutes),
        )

    async def resolve_credential(self, token: str) -> UserT | None:
        """Access token -> user, or None if bad signature/expired/wrong user."""
        if not token:
            return None
        payload = self._decode(token, ACCESS_TOKEN_TYPE)
        if payload is None:
            return None
        try:
            user_id = uuid.UUID(str(payload["sub"]))
        except ValueError, AttributeError, TypeError:
            return None
        user = await self.get_user_by_id(user_id)
        if user is None or not user.is_active:
            return None
        return user

    async def revoke_credential(self, token: str) -> None:
        """No-op: stateless tokens can't be revoked server-side (placeholder)."""

    def _require_refresh_model(self) -> type[FastAuthRefreshTokenMixin]:
        """Return refresh_model or fail fast when the adapter is miswired."""
        if self.refresh_model is None:
            msg = "SQLAlchemyJWTAdapter requires refresh_model (pass via FastAuth)."
            raise ValueError(msg)
        return self.refresh_model

    async def _revoke_refresh_family(self, user_id: uuid.UUID) -> None:
        """Delete every outstanding refresh row for a user (reuse defense)."""
        model = self._require_refresh_model()
        await self.db_session.execute(
            delete(model).where(model.user_id == user_id)  # type: ignore[attr-defined]
        )
        await self.db_session.flush()

    async def issue_refresh_token(self, user: UserT) -> str:
        """Mint a refresh JWT and store its row for single-use rotation."""
        cfg = self._require_config()
        model = self._require_refresh_model()
        now = datetime.now(UTC)
        expires_at = now + timedelta(days=cfg.refresh_token_expire_days)
        jti = uuid.uuid4()
        token = jwt.encode(
            {
                "sub": str(user.id),
                "exp": expires_at,
                "iat": now,
                "jti": jti.hex,
                "type": REFRESH_TOKEN_TYPE,
            },
            cfg.secret_key,
            algorithm=cfg.algorithm,
        )
        self.db_session.add(
            model(  # type: ignore[call-arg]
                id=jti,  # type: ignore[call-arg]
                user_id=user.id,  # type: ignore[call-arg]
                created_at=now,  # type: ignore[call-arg]
                expires_at=expires_at,  # type: ignore[call-arg]
            )
        )
        await self.db_session.flush()
        return token

    async def consume_refresh_token(self, token: str) -> UserT | None:
        """Validate a refresh JWT single-use (burn its row) -> user or None.

        A signed-but-unknown token means it was already consumed or revoked,
        so assume theft and revoke the user's whole refresh family.
        """
        if not token:
            return None
        payload = self._decode(token, REFRESH_TOKEN_TYPE)
        if payload is None:
            return None
        try:
            jti = uuid.UUID(str(payload.get("jti")))
            user_id = uuid.UUID(str(payload["sub"]))
        except ValueError, AttributeError, TypeError:
            return None
        model = self._require_refresh_model()
        row: Any = await self.db_session.get(model, jti)
        if row is None:
            await self._revoke_refresh_family(user_id)
            return None
        expires = row.expires_at
        if expires is None:
            await self.db_session.delete(row)
            await self.db_session.flush()
            return None
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=UTC)
        if expires <= datetime.now(UTC):
            await self.db_session.delete(row)
            await self.db_session.flush()
            return None
        user = await self.get_user_by_id(row.user_id)
        await self.db_session.delete(row)
        await self.db_session.flush()
        if user is None or not user.is_active:
            return None
        return user

    async def revoke_refresh_token(self, token: str) -> None:
        """Delete the refresh row for a (possibly expired) token; no raise."""
        if not token or self.jwt_config is None or self.refresh_model is None:
            return
        try:
            payload = jwt.decode(
                token,
                self.jwt_config.secret_key,
                algorithms=[self.jwt_config.algorithm],
                options={"verify_exp": False},
            )
            jti = uuid.UUID(str(payload.get("jti")))
        except jwt.InvalidTokenError, ValueError, AttributeError, TypeError:
            return
        row = await self.db_session.get(self.refresh_model, jti)
        if row is not None:
            await self.db_session.delete(row)
            await self.db_session.flush()
