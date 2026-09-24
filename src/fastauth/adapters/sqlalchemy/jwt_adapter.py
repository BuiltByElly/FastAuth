import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt
from pwdlib import PasswordHash
from sqlalchemy import delete, inspect, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import Adapter
from fastauth.adapters.exceptions import RefreshTokenReused
from fastauth.config import JWTConfig
from fastauth.protocols import SessionT, UserT
from fastauth.security import hash_password

from .models import FastAuthRefreshTokenMixin

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
        session_expire_days: int = 7,
        password_hasher: PasswordHash | None = None,
    ):
        """Bind a request session plus the app's User model (no sessions)."""
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

    async def revoke_credential(self, token: str) -> str | None:
        """No-op: stateless access tokens can't be revoked server-side."""

    def _require_refresh_model(self) -> type[FastAuthRefreshTokenMixin]:
        """Return refresh_model or fail fast when the adapter is miswired."""
        if self.refresh_model is None:
            msg = "SQLAlchemyJWTAdapter requires refresh_model (pass via FastAuth)."
            raise ValueError(msg)
        return self.refresh_model

    async def _revoke_refresh_family(self, user_id: uuid.UUID) -> bool:
        """Stamp revoked_at on every refresh row for a user (reuse defense)."""
        model = self._require_refresh_model()
        await self.db_session.execute(
            update(model)
            .where(model.user_id == user_id)  # type: ignore[attr-defined]
            .values(revoked_at=datetime.now(UTC))
        )
        await self.db_session.flush()
        return True

    async def purge_expired_refresh_tokens(self) -> int:
        """Delete expired refresh-token rows; returns the deleted count.

        Outstanding and consumed-but-unexpired rows are kept. Flushes;
        the caller commits.
        """
        model = self._require_refresh_model()
        result = await self.db_session.execute(
            delete(model).where(
                or_(
                    model.expires_at.is_(None),  # type: ignore[attr-defined]
                    model.expires_at <= datetime.now(UTC),  # type: ignore[attr-defined]
                )
            )
        )
        await self.db_session.flush()
        return result.rowcount  # type: ignore[attr-defined]

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
        """Validate and single-use-consume a refresh JWT.

        Returns:
            The user, if the token was valid and previously unused (now stamped
            as used). ``None`` if missing, malformed, unknown, expired, or
            already-revoked.

        Raises:
            RefreshTokenReused: the token had already been used once — the whole
                refresh family has just been revoked.
        """
        if not token:
            return None

        payload = self._decode(token, REFRESH_TOKEN_TYPE)
        if payload is None:
            return None

        try:
            jti = uuid.UUID(str(payload.get("jti")))
            user_id = uuid.UUID(str(payload["sub"]))
        except ValueError, AttributeError, TypeError, KeyError:
            return None

        model = self._require_refresh_model()
        row: Any = await self.db_session.get(model, jti)

        if row is None or row.revoked_at is not None:
            return None
        if row.used_at is not None:
            await self._revoke_refresh_family(user_id)
            await self.db_session.flush()
            raise RefreshTokenReused(user_id)

        expires_at = row.expires_at
        if expires_at is not None and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

        if expires_at is None or expires_at <= datetime.now(UTC):
            row.revoked_at = datetime.now(UTC)
            await self.db_session.flush()
            return None

        user = await self.get_user_by_id(row.user_id)
        if user is None or not user.is_active:
            return None

        row.used_at = datetime.now(UTC)
        await self.db_session.flush()
        return user

    async def revoke_refresh_token(self, token: str) -> str | None:
        """Stamp the refresh row consumed for a (possibly expired) token.

        The row is kept (not deleted) so replaying a logged-out token is
        still recognizable as reuse. Never raises.

        returns the user's id for the on_after_logout hook
        """
        user_id = ""
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
            user_id = str(payload.get("sub"))
        except jwt.InvalidTokenError, ValueError, AttributeError, TypeError:
            return
        row: Any = await self.db_session.get(self.refresh_model, jti)
        if row is not None and row.used_at is None and row.revoked_at is None:
            row.used_at = datetime.now(UTC)
            row.revoked_at = datetime.now(UTC)
            await self.db_session.flush()
        return user_id
