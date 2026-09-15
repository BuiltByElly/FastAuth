# fastauth/models.py
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column


class FastAuthUserMixin:
    """A Base class for the required columns for Users.

    Args:
        id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid7)
        email: Mapped[str] = mapped_column(String, unique=True, index=True)
        hashed_password: Mapped[str] = mapped_column(String)
        is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    """

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid7)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class FastAuthSessionMixin:
    """A Base class for the required columns for Sessions.

    Args:
        id: Mapped[str] = mapped_column(String, primary_key=True)
        expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
        created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    Important:
        create a foreign key in its child class
        user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id")).
        replace "users" with the appropriate table name
    """

    id: Mapped[str] = mapped_column(String, primary_key=True)
    # user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
