import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from fastauth.adapters import Adapter
from fastauth.adapters.exceptions import EmailAlreadyRegistered
from fastauth.protocols import OIDCAccountT, UserT
from fastauth.schemas import OIDCUserInfo


class OIDCAccountAdapterMixin(Adapter[UserT, OIDCAccountT, Any]):
    async def get_oidc_account(
        self, provider: str, provider_user_id: str
    ) -> OIDCAccountT | None:
        model = self.require_oidc_account_model()
        result = await self.db_session.execute(
            select(model).where(
                model.provider == provider,
                model.provider_user_id == provider_user_id,
            )
        )
        return result.scalar_one_or_none()

    async def create_user_from_oidc(self, user_info: OIDCUserInfo) -> UserT:
        user = self.user_model(
            email=user_info.email,  # type: ignore
            is_active=True,  # type: ignore
        )
        self.db_session.add(user)
        try:
            await self.db_session.flush()
        except IntegrityError as e:
            # The email already belongs to an account (typically a password
            # one). An IdP email claim must never implicitly take it over.
            await self.db_session.rollback()
            raise EmailAlreadyRegistered(user_info.email) from e

        model = self.require_oidc_account_model()
        account = model(
            user_id=user.id,  # type: ignore
            provider=user_info.provider,
            provider_user_id=user_info.provider_user_id,
        )
        self.db_session.add(account)
        await self.db_session.flush()

        return user


class PasswordResetTokenAdapterMixin(Adapter[UserT, Any, Any]):
    """Shared reset-token logic. Works for either strategy — relies only
    on `require_password_reset_model()` and `get_user_by_id()`, which
    every concrete adapter already provides."""

    async def create_password_reset_token(self, user: UserT) -> str:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

        model = self.require_password_reset_model()
        # Invalidate outstanding tokens for this user so repeated
        # forgot-password calls can't stockpile valid tokens.
        await self.db_session.execute(
            update(model)
            .where(
                model.user_id == user.id,  # type: ignore[attr-defined]
                model.used_at.is_(None),  # type: ignore[attr-defined]
            )
            .values(used_at=datetime.now(UTC))
        )
        row = model(
            user_id=user.id,  # type: ignore[arg-type]
            token_hash=token_hash,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        self.db_session.add(row)
        await self.db_session.flush()
        return raw_token  # only the raw value goes to the hook/email — never stored

    async def consume_password_reset_token(self, token: str) -> UserT | None:
        if not token or not isinstance(token, str):
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        model = self.require_password_reset_model()
        # FOR UPDATE serializes concurrent consumes of the same token so a
        # race can't redeem it twice (SQLite ignores the lock, but Postgres
        # honors it — harmless on both).
        row: Any = await self.db_session.scalar(
            select(model)
            .where(model.token_hash == token_hash)  # type: ignore[attr-defined]
            .with_for_update()
        )

        if row is None or row.used_at is not None:
            return None  # never existed, or already used

        expires_at = row.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= datetime.now(UTC):
            return None  # expired

        # Burn first so the token is single-use even when the account is
        # gone/inactive — a retry must not become an account-state oracle.
        row.used_at = datetime.now(UTC)
        await self.db_session.flush()

        user = await self.get_user_by_id(row.user_id)
        if user is None or not user.is_active:  # type: ignore[operator]
            return None

        return user

    async def set_password(self, user: UserT, new_password: str) -> None:
        if self.password_hasher is None:
            raise ValueError(
                "password_hasher is required to set passwords "
                "(pass PasswordConfig hash_schemes via FastAuth)."
            )
        user.hashed_password = self.password_hasher.hash(  # type: ignore[assignment]
            new_password
        )
        await self.db_session.flush()
