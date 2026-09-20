"""Integration: what actually lands in the database on signup.

Proves the stored value is an argon2 hash of the plaintext — never the
plaintext itself and never a `SecretStr('**********')` repr.
"""

from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select

from fastauth.adapters import SQLAlchemySessionAdapter
from fastauth.security import verify_password
from tests.conftest import Session, User, build_jwt_app

PLAINTEXT = "super-secret-password"


async def _stored_hash(session_factory):
    async with session_factory() as session:
        user = (await session.execute(select(User))).scalar_one()
        return user.hashed_password


def _assert_is_hash_of_plaintext(stored, plaintext=PLAINTEXT):
    assert isinstance(stored, str)
    assert stored.startswith("$argon2"), f"expected argon2 hash, got {stored[:30]!r}"
    assert plaintext not in stored
    assert "**********" not in stored
    assert verify_password(plaintext, stored) is True


async def test_session_signup_stores_hash_not_secret(session_client, session_factory):
    response = session_client.post(
        "/auth/signup", json={"email": "u@example.com", "password": PLAINTEXT}
    )
    assert response.status_code == 200
    _assert_is_hash_of_plaintext(await _stored_hash(session_factory))
    # …and the round-trip still works (hash matches at login).
    assert (
        session_client.post(
            "/auth/login", json={"email": "u@example.com", "password": PLAINTEXT}
        ).status_code
        == 200
    )


async def test_jwt_signup_stores_hash_not_secret(
    get_db, test_config, jwt_config, session_factory
):
    config = test_config.model_copy(update={"jwt": jwt_config})
    app, _ = build_jwt_app(get_db, config=config)
    with TestClient(app) as client:
        response = client.post(
            "/auth/signup", json={"email": "u@example.com", "password": PLAINTEXT}
        )
        assert response.status_code == 200
    _assert_is_hash_of_plaintext(await _stored_hash(session_factory))


async def test_adapter_create_user_unwraps_secret(session_factory):
    """Adapter-level: a SecretStr password still becomes a verifiable hash."""
    async with session_factory() as session:
        adapter = SQLAlchemySessionAdapter(
            db_session=session, user_model=User, session_model=Session
        )
        user = await adapter.create_user(
            {"email": "a@b.com", "password": SecretStr(PLAINTEXT)}
        )
        await session.commit()
    _assert_is_hash_of_plaintext(user.hashed_password)


async def test_unprotected_422_echoes_password(get_db, test_config):
    """Documents the residual risk without the handler: FastAPI's default
    422 handler echoes raw inputs, SecretStr masking notwithstanding."""
    from tests.conftest import build_session_app

    app, _ = build_session_app(get_db, config=test_config)
    with TestClient(app) as client:
        response = client.post(
            "/auth/signup", json={"email": "u@example.com", "password": "zq9"}
        )
        assert response.status_code == 422
        assert "zq9" in response.text
