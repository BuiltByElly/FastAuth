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
from datetime import datetime

from pydantic import EmailStr
from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column


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
    from fastauth.models import FastAuthUserMixin

    class Base(DeclarativeBase):
        pass

    class Users(Base, FastAuthUserMixin):
        __tablename__ = "users"

        # add your own columns as needed:
        # name: Mapped[str] = mapped_column(String, nullable=True)
    ```
    """

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid7)
    email: Mapped[EmailStr] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


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
    from fastauth.models import FastAuthSessionMixin

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
    from fastauth.models import FastAuthRefreshTokenMixin

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
