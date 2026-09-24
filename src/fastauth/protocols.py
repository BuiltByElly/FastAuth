"""ORM-neutral contracts for the models FastAuth operates on.

This module imports nothing ORM-specific (only ``uuid``, ``datetime`` and
``typing``). Backends satisfy these contracts structurally — a model is
compatible if it simply *has* the declared attributes, no inheritance or
registration required. The generic ``TypeVar``s in ``adapters`` are bound
to these protocols instead of to any ORM's mixins.

SQLAlchemy users keep using the concrete mixins in
``fastauth.adapters.sqlalchemy.models``, which satisfy these protocols.

The ``TypeVar``s below are intentionally *unbound*: static checkers cannot
prove ORM-descriptor attributes (e.g. SQLAlchemy ``Mapped[...]``, whose
mutability makes it invariant) satisfy protocol members, so a bound would
reject every valid model. Conformance is enforced at runtime instead —
``ensure_model_compliance`` at startup plus the adapter test suite.
"""

import uuid
from datetime import datetime
from typing import Protocol, TypeVar, runtime_checkable


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


# Unbound type variables for positions that accept *any* backend's model
# (e.g. ``user_model: type[UserT]`` on constructors). They are deliberately
# NOT bound to the protocols above: SQLAlchemy ``Mapped[...]`` attributes
# are invariant, so no static formulation can prove conformance — the
# annotation would reject every valid model. Each use-site binds
# independently, preserving internal type flow without false positives.
UserT = TypeVar("UserT")
SessionT = TypeVar("SessionT")
RefreshT = TypeVar("RefreshT")
RateLimitT = TypeVar("RateLimitT")


def _required_attributes(protocol: type) -> tuple[str, ...]:
    """Attribute names a model must provide to satisfy a protocol."""
    return tuple(getattr(protocol, "__annotations__", {}))


def ensure_model_compliance(model: type, protocol: type, *, name: str) -> None:
    """Fail fast if a model lacks attributes its protocol requires.

    Only attribute *names* are checked: static checkers cannot verify the
    types of ORM descriptors (e.g. SQLAlchemy ``Mapped[...]``), so the
    contract beyond names is enforced by the adapter conformance tests.
    Raises ``TypeError`` with the missing attributes listed.

    Args:
        model: The app's model class to check.
        protocol: One of the protocols in this module.
        name: What to call the model in the error (e.g. "user_model").
    """
    required = _required_attributes(protocol)
    missing = [attr for attr in required if not hasattr(model, attr)]
    if missing:
        raise TypeError(
            f"{name} {model.__name__!r} does not satisfy "
            f"{protocol.__name__}: missing attributes: {', '.join(missing)}. "
            f"Add columns (or attributes) named: {', '.join(required)}."
        )
