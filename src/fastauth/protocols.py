"""ORM-neutral contracts for the models FastAuth operates on.

This module imports nothing ORM-specific (only ``uuid``, ``datetime`` and
``typing``). Backends satisfy these contracts structurally — a model is
compatible if it simply *has* the declared attributes, no inheritance or
registration required. The generic ``TypeVar``s in ``adapters`` are bound
to these protocols instead of to any ORM's mixins.

SQLAlchemy users keep using the concrete mixins in
``fastauth.adapters.sqlalchemy.models``, which satisfy these protocols.
"""

import uuid
from datetime import datetime
from typing import Protocol, runtime_checkable


@runtime_checkable
class UserProtocol(Protocol):
    """Anything FastAuth can authenticate as a user."""

    id: uuid.UUID
    email: str
    hashed_password: str
    is_active: bool


@runtime_checkable
class SessionProtocol(Protocol):
    """Anything FastAuth can use as a server-side session row."""

    id: uuid.UUID
    user_id: uuid.UUID
    expires_at: datetime
    created_at: datetime


@runtime_checkable
class RefreshTokenProtocol(Protocol):
    """Anything FastAuth can use as a refresh-token row."""

    id: uuid.UUID
    user_id: uuid.UUID
    expires_at: datetime
    created_at: datetime
    used_at: datetime | None
    revoked_at: datetime | None


@runtime_checkable
class RateLimitProtocol(Protocol):
    """Anything FastAuth can use as a rate-limit counter row."""

    key: str
    count: int
    window_start: datetime
