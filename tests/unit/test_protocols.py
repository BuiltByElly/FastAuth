"""Unit tests: ORM-neutral protocols and startup compliance checks."""

import ast

import pytest

from fastauth.protocols import (
    RateLimitProtocol,
    RefreshTokenProtocol,
    SessionProtocol,
    UserProtocol,
    UserT,
    ensure_model_compliance,
)
from tests.conftest import RateLimitRow, RefreshToken, Session, User


def test_protocols_import_nothing_orm_specific():
    """protocols.py must stay importable without any ORM installed."""
    from pathlib import Path

    tree = ast.parse(Path("src/fastauth/protocols.py").read_text())
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imports.add((node.module or "").split(".")[0])
    assert imports <= {"uuid", "datetime", "typing"}, imports


def test_typevars_are_unbound():
    """Bound TypeVars would reintroduce the Mapped-invariance false positives."""
    assert UserT.__bound__ is None


@pytest.mark.parametrize(
    ("model", "protocol", "name"),
    [
        (User, UserProtocol, "user_model"),
        (Session, SessionProtocol, "session_model"),
        (RefreshToken, RefreshTokenProtocol, "refresh_model"),
        (RateLimitRow, RateLimitProtocol, "rate_limit_model"),
    ],
)
def test_valid_models_pass_compliance(model, protocol, name):
    ensure_model_compliance(model, protocol, name=name)


def test_missing_attributes_raise_clear_error():
    class PartialUser:
        id = None
        email = "x@y.zz"

    with pytest.raises(TypeError) as exc:
        ensure_model_compliance(PartialUser, UserProtocol, name="user_model")
    message = str(exc.value)
    assert "user_model" in message
    assert "PartialUser" in message
    assert "hashed_password" in message and "is_active" in message


def test_empty_model_lists_everything_missing():
    class Empty:
        pass

    with pytest.raises(TypeError) as exc:
        ensure_model_compliance(Empty, SessionProtocol, name="session_model")
    for attr in ("id", "user_id", "expires_at", "created_at"):
        assert attr in str(exc.value)


def test_auth_construction_rejects_noncompliant_model(get_db):
    """Fail fast at startup — not deep inside the first request."""
    from fastauth import SessionAuth
    from fastauth.adapters.sqlalchemy import SQLAlchemySessionAdapter

    class NotAUser:
        pass

    with pytest.raises(TypeError, match="user_model"):
        SessionAuth(
            adapter=SQLAlchemySessionAdapter,
            db_session_dependency=get_db,
            user_model=NotAUser,
            session_model=Session,
        )
