# fastauth/models.py
"""Column mixins for wiring FastAuth into your own SQLAlchemy models.

These classes are **mixins, not models**: they only declare columns.
You inherit from them alongside your own declarative `Base` to add the
columns FastAuth needs, while keeping full ownership of table names,
relationships, and any extra columns.

Designed for SQLAlchemy 2.0 style (`Mapped` + `mapped_column`).
SQLModel compatibility is not officially supported/tested.
"""

import uuid
from datetime import UTC, datetime

from pydantic import EmailStr
from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column
from uuid6 import uuid7


class FastAuthUserMixin:
    """Adds the required FastAuth columns to a user model.

    Inherit from this mixin (plus your declarative `Base`) in your own
    `User` model. It does not define `__tablename__` — you do.

    Attributes:
        id: Primary key, auto-generated `uuid.uuid7` (time-ordered UUID).
        email: Unique, indexed login identifier.
        hashed_password: Argon2 (or other) password hash. Never store
            plaintext here — FastAuth hashes on register/login.
        is_active: Soft on/off switch for the account. FastAuth treats
            `False` as "cannot log in", without deleting the row.

    Example:
    ```python
    from sqlalchemy.orm import DeclarativeBase
    from fastauth.adapters.sqlalchemy.models import FastAuthUserMixin

    class Base(DeclarativeBase):
        pass

    class Users(Base, FastAuthUserMixin):
        __tablename__ = "users"

        # add your own columns as needed:
        # name: Mapped[str] = mapped_column(String, nullable=True)
    ```
    """

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid7)
    email: Mapped[EmailStr] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    password_changed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )


class FastAuthSessionMixin:
    """Adds the required FastAuth columns to a session model.

    Inherit from this mixin (plus your declarative `Base`) in your own
    session model. It does not define `__tablename__` or `user_id` —
    you must add `user_id` yourself so the foreign key can point at
    whatever your users table is actually called.

    Attributes:
        id: Primary key, opaque session token. Random ``uuid4`` — never
            time-ordered (``uuid7`` would be predictable across logins).
        expires_at: Timezone-aware expiry timestamp. Expired sessions
            are rejected by FastAuth.
        created_at: Timezone-aware creation timestamp.

    Example:
    ```python
    import uuid
    from sqlalchemy import ForeignKey
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
    from fastauth.adapters.sqlalchemy.models import FastAuthSessionMixin

    class Base(DeclarativeBase):
        pass

    class Sessions(Base, FastAuthSessionMixin):
        __tablename__ = "sessions"

        # Required: link each session back to a user.
        # Replace "users.id" with your actual user table name if different.
        user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    ```
    """

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class FastAuthRefreshTokenMixin:
    """Adds the required FastAuth columns to a refresh-token model.

    JWT strategy only. Each row tracks one outstanding refresh token by its
    JWT ``jti`` so rotation is single-use: consuming a refresh token stamps
    its ``used_at`` (soft delete — the row is kept), and presenting an
    already-consumed token revokes the whole family (reuse detection). The
    row is kept deliberately: it lets rotation distinguish "never existed"
    (plain reject) from "existed and was already used" (theft response).
    It does not define ``__tablename__`` or ``user_id`` — you must add
    ``user_id`` yourself so the foreign key can point at whatever your
    users table is actually called.

    Attributes:
        id: Primary key, mirrors the refresh JWT's ``jti`` (random
            ``uuid4`` — never time-ordered, so ids are unpredictable).
        expires_at: Timezone-aware expiry timestamp, mirrors the JWT
            ``exp``. Expired tokens are rejected by FastAuth.
        created_at: Timezone-aware creation timestamp.
        consumed_at: Timezone-aware timestamp of single-use consumption,
            or None while outstanding. Replaying a consumed token triggers
            family revocation. Nullable so existing tables gain the column
            via a trivial `ALTER TABLE ADD COLUMN`.

    Example:
    ```python
    import uuid
    from sqlalchemy import ForeignKey
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
    from fastauth.adapters.sqlalchemy.models import FastAuthRefreshTokenMixin

    class Base(DeclarativeBase):
        pass

    class RefreshTokens(Base, FastAuthRefreshTokenMixin):
        __tablename__ = "refresh_tokens"

        # Required: link each token back to a user.
        # Replace "users.id" with your actual user table name if different.
        user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    ```
    """

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, default=uuid.uuid4, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )


class FastAuthRateLimitMixin:
    """Inherit + add __tablename__, same pattern as other FastAuth mixins."""

    key: Mapped[str] = mapped_column(primary_key=True)
    count: Mapped[int] = mapped_column(default=0)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class FastAuthPasswordResetTokensMixin:
    """Adds the required FastAuth columns to a `password_reset_tokens` model.

    Inherit from this mixin (plus your declarative `Base`) in your own
    `password_reset_tokens` model. It does not define `__tablename__` and the necessary foreign key — you do.

    Only the SHA-256 hex of the raw token is stored — the raw value is
    emailed to the user once and never touches the database.

    Attributes:
        id: Primary key, random `uuid4` (unpredictable token-row id).
        user_id: Foreign key to the `users` table.
        token_hash: Hex SHA-256 of the raw reset token. Unique + indexed
            for single-row lookup; never the raw token itself.
        expires_at: Timezone-aware expiry timestamp (15-minute lifetime).
        used_at: Timezone-aware consumption timestamp, None while
            outstanding. Single-use: replaying a consumed token is rejected.

    Example:
    ```python
    from sqlalchemy.orm import DeclarativeBase
    from fastauth.adapters.sqlalchemy.models import FastAuthPasswordResetTokensMixin

    class Base(DeclarativeBase):
        pass

    class PasswordResetToken(Base, FastAuthPasswordResetTokensMixin):
        __tablename__ = "password_reset_tokens"

        user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    ```
    """

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), default=None, nullable=True
    )


class FastAuthOAuthAccountMixin:
    """Links one OAuth identity to one of your users. Does not define
    `__tablename__`, `user_id`, or the unique constraint — you do.
    Used by OIDCAuth and OAuth2Auth.

    Example:
    ```python
    import uuid
    from sqlalchemy import ForeignKey, UniqueConstraint
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
    from fastauth.adapters.sqlalchemy.models import FastAuthOAuthAccountMixin

    class Base(DeclarativeBase):
        pass

    class OAuthAccount(Base, FastAuthOAuthAccountMixin):
        __tablename__ = "oauth_accounts"

        # Required: link each token back to a user.
        # Replace "users.id" with your actual user table name if different.
        user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)

        __table_args__ = (
                UniqueConstraint("provider", "provider_user_id", name="uq_oauth_provider_account"), # mandatory
                UniqueConstraint("provider", "user_id", name="uq_oauth_provider_per_user"),  # optional
            )
    ```
    """

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    provider: Mapped[str]
    provider_user_id: Mapped[str]
