"""Unit tests: adapter edge branches unreachable (or awkward) over HTTP."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest
from sqlalchemy import select

from fastauth.adapters.sqlalchemy import SQLAlchemyJWTAdapter, SQLAlchemySessionAdapter
from fastauth.config import JWTConfig
from fastauth.security import build_hasher
from tests.conftest import (
    TEST_SECRET,
    PasswordResetToken,
    RefreshToken,
    Session,
    User,
    create_user,
)


@pytest.fixture
def jwt_cfg():
    return JWTConfig(secret_key=TEST_SECRET)


@pytest.fixture
async def db_session(session_factory):
    async with session_factory() as session:
        yield session


def session_adapter(db_session):
    return SQLAlchemySessionAdapter(
        db_session,
        User,
        Session,
        password_hasher=build_hasher(None),
        password_reset_token_model=PasswordResetToken,
    )


def jwt_adapter(db_session, jwt_cfg):
    return SQLAlchemyJWTAdapter(
        db_session,
        User,
        jwt_config=jwt_cfg,
        refresh_model=RefreshToken,
        password_hasher=build_hasher(None),
        password_reset_token_model=PasswordResetToken,
    )


async def test_get_unknown_user_returns_none(db_session):
    adapter = session_adapter(db_session)
    assert await adapter.get_user_by_email("nobody@example.com") is None
    assert await adapter.get_user_by_id(uuid.uuid4()) is None


async def test_revoke_unknown_or_garbage_never_raises(db_session):
    adapter = session_adapter(db_session)
    await adapter.revoke_credential(str(uuid.uuid4()))
    await adapter.revoke_credential("garbage")
    await adapter.revoke_credential("")


async def test_resolve_empty_token_is_none(db_session, jwt_cfg):
    adapter = jwt_adapter(db_session, jwt_cfg)
    assert await adapter.resolve_credential("") is None


async def test_jwt_adapter_without_config_fails_fast(db_session):
    adapter = SQLAlchemyJWTAdapter(db_session, User, refresh_model=RefreshToken)
    await create_user_via(db_session, adapter)
    user = await adapter.get_user_by_email("u@example.com")
    with pytest.raises(ValueError, match="jwt_config"):
        await adapter.issue_credential(user)
    with pytest.raises(ValueError, match="jwt_config"):
        await adapter.resolve_credential("whatever")


async def test_refresh_without_model_fails_fast(db_session, jwt_cfg):
    adapter = SQLAlchemyJWTAdapter(db_session, User, jwt_config=jwt_cfg)
    await create_user_via(db_session, adapter)
    user = await adapter.get_user_by_email("u@example.com")
    with pytest.raises(ValueError, match="refresh_model"):
        await adapter.issue_refresh_token(user)
    token = _mint({"sub": str(user.id), "jti": uuid.uuid4().hex, "type": "refresh"})
    with pytest.raises(ValueError, match="refresh_model"):
        await adapter.consume_refresh_token(token)


async def test_consume_unparsable_claims_is_none(db_session, jwt_cfg):
    adapter = jwt_adapter(db_session, jwt_cfg)
    # Valid signature + sub, but garbage jti → UUID parse fails.
    bad_jti = _mint({"sub": str(uuid.uuid4()), "jti": "not-a-uuid", "type": "refresh"})
    assert await adapter.consume_refresh_token(bad_jti) is None
    # Missing sub → required-claim check fails inside decode.
    no_sub = _mint({"jti": uuid.uuid4().hex, "type": "refresh"})
    assert await adapter.consume_refresh_token(no_sub) is None


async def test_consume_unknown_jti_is_plain_reject(db_session, jwt_cfg, session_factory):
    await create_user(session_factory)
    adapter = jwt_adapter(db_session, jwt_cfg)
    user = await adapter.get_user_by_email("u@example.com")
    token = _mint({"sub": str(user.id), "jti": uuid.uuid4().hex, "type": "refresh"})
    assert await adapter.consume_refresh_token(token) is None


async def test_consume_revoked_row_is_none(db_session, jwt_cfg, session_factory):
    await create_user(session_factory)
    adapter = jwt_adapter(db_session, jwt_cfg)
    user = await adapter.get_user_by_email("u@example.com")
    token = await adapter.issue_refresh_token(user)
    await db_session.commit()
    await adapter.revoke_refresh_token(token)
    await db_session.commit()
    assert await adapter.consume_refresh_token(token) is None


async def test_consume_expired_row_stamped_and_none(db_session, jwt_cfg, session_factory):
    await create_user(session_factory)
    adapter = jwt_adapter(db_session, jwt_cfg)
    user = await adapter.get_user_by_email("u@example.com")
    token = await adapter.issue_refresh_token(user)
    await db_session.commit()
    jti = uuid.UUID(pyjwt.decode(token, options={"verify_signature": False})["jti"])
    row = await db_session.get(RefreshToken, jti)
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()
    # Fresh token with a valid exp but a stale row exercises the row-side check:
    # soft delete stamps revoked_at (hard deletion is purge's job).
    assert await adapter.consume_refresh_token(token) is None
    await db_session.commit()
    row = await db_session.get(RefreshToken, jti)
    assert row is not None and row.revoked_at is not None


async def test_revoke_refresh_token_marks_row(db_session, jwt_cfg, session_factory):
    await create_user(session_factory)
    adapter = jwt_adapter(db_session, jwt_cfg)
    user = await adapter.get_user_by_email("u@example.com")
    token = await adapter.issue_refresh_token(user)
    await db_session.commit()
    await adapter.revoke_refresh_token(token)
    await db_session.commit()
    jti = uuid.UUID(pyjwt.decode(token, options={"verify_signature": False})["jti"])
    row = await db_session.get(RefreshToken, jti)
    assert row.used_at is not None and row.revoked_at is not None


async def test_revoke_refresh_token_garbage_never_raises(db_session, jwt_cfg):
    adapter = jwt_adapter(db_session, jwt_cfg)
    await adapter.revoke_refresh_token("garbage")
    await adapter.revoke_refresh_token("")


async def test_reset_token_is_single_use(db_session, session_factory):
    await create_user(session_factory)
    adapter = session_adapter(db_session)
    user = await adapter.get_user_by_email("u@example.com")
    raw = await adapter.create_password_reset_token(user)
    await db_session.commit()
    # Only the hash is stored — never the raw value.
    stored = (await db_session.execute(select(PasswordResetToken))).scalars().all()
    assert len(stored) == 1
    assert stored[0].token_hash != raw
    assert raw not in stored[0].token_hash

    consumed = await adapter.consume_password_reset_token(raw)
    assert consumed is not None and consumed.id == user.id
    await db_session.commit()
    # Replay is rejected.
    assert await adapter.consume_password_reset_token(raw) is None


async def test_reset_token_unknown_and_garbage_are_none(db_session):
    adapter = session_adapter(db_session)
    assert await adapter.consume_password_reset_token("never-issued") is None
    assert await adapter.consume_password_reset_token("") is None


async def test_reset_token_expired_is_none(db_session, session_factory):
    await create_user(session_factory)
    adapter = session_adapter(db_session)
    user = await adapter.get_user_by_email("u@example.com")
    raw = await adapter.create_password_reset_token(user)
    await db_session.commit()
    row = (await db_session.execute(select(PasswordResetToken))).scalar_one()
    row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    await db_session.commit()
    assert await adapter.consume_password_reset_token(raw) is None


async def test_reset_token_second_request_invalidates_first(
    db_session, session_factory
):
    await create_user(session_factory)
    adapter = session_adapter(db_session)
    user = await adapter.get_user_by_email("u@example.com")
    first = await adapter.create_password_reset_token(user)
    await db_session.commit()
    second = await adapter.create_password_reset_token(user)
    await db_session.commit()
    assert await adapter.consume_password_reset_token(first) is None
    consumed = await adapter.consume_password_reset_token(second)
    assert consumed is not None


async def test_reset_token_requires_model(db_session, session_factory):
    await create_user(session_factory)
    bare = SQLAlchemySessionAdapter(
        db_session, User, Session, password_hasher=build_hasher(None)
    )
    user = await bare.get_user_by_email("u@example.com")
    with pytest.raises(ValueError, match="password_reset_token_model"):
        await bare.create_password_reset_token(user)
    with pytest.raises(ValueError, match="password_reset_token_model"):
        await bare.consume_password_reset_token("anything")


async def test_set_password_rehashes(db_session, session_factory):
    from fastauth.security import verify_password

    await create_user(session_factory, password="long-enough")
    adapter = session_adapter(db_session)
    user = await adapter.get_user_by_email("u@example.com")
    await adapter.set_password(user, "brand-new-password")
    await db_session.commit()
    assert verify_password("brand-new-password", user.hashed_password) is True
    assert verify_password("long-enough", user.hashed_password) is False


async def create_user_via(db_session, adapter):
    user = await adapter.create_user({"email": "u@example.com", "password": "long-enough"})
    await db_session.commit()
    return user


def _mint(claims):
    now = datetime.now(UTC)
    base = {"exp": now + timedelta(days=7), "iat": now}
    base.update(claims)
    return pyjwt.encode(base, TEST_SECRET, algorithm="HS256")
