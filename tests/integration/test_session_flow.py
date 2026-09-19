"""Integration: full session-strategy lifecycle over HTTP."""

import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.conftest import Session, User, build_session_app, cookie_value


@pytest.fixture
def app_pair(get_db, test_config):
    """Session app + auth instance (rate limiting disabled)."""
    return build_session_app(get_db, config=test_config)


@pytest.fixture
def client(app_pair):
    app, _ = app_pair
    with TestClient(app) as client:
        yield client


def signup(client, email="u@example.com", password="long-enough", **extra):
    return client.post("/auth/signup", json={"email": email, "password": password, **extra})


def login(client, email="u@example.com", password="long-enough"):
    return client.post("/auth/login", json={"email": email, "password": password})


def test_signup_returns_public_fields_only(client):
    response = signup(client)
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "u@example.com"
    assert body["is_active"] is True
    assert uuid.UUID(body["id"])
    assert "hashed_password" not in body
    assert "password" not in body


def test_signup_rejects_duplicate_email(client):
    assert signup(client).status_code == 200
    response = signup(client)
    assert response.status_code == 400
    assert response.json()["detail"] == "Email already registered."


def test_signup_rejects_short_password(client):
    assert signup(client, password="short").status_code == 422


def test_login_sets_session_cookie(client):
    signup(client)
    response = login(client)
    assert response.status_code == 200
    assert response.json()["success"] is True
    set_cookie = response.headers["set-cookie"]
    assert "fastauth_session=" in set_cookie
    session_id = cookie_value(set_cookie)
    assert uuid.UUID(session_id)  # opaque UUID token


def test_login_wrong_password_is_401(client):
    signup(client)
    response = login(client, password="wrong-pass-1")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials."


def test_login_unknown_email_is_401(client):
    response = login(client, email="nobody@example.com")
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials."


async def test_login_inactive_user_is_403(client, session_factory):
    signup(client)
    async with session_factory() as session:
        user = (await session.execute(select(User))).scalar_one()
        user.is_active = False
        await session.commit()
    response = login(client)
    assert response.status_code == 403


def test_me_returns_user_with_cookie(client):
    signup(client)
    login(client)
    response = client.get("/auth/me")
    assert response.status_code == 200
    assert response.json()["email"] == "u@example.com"


def test_me_without_cookie_is_401(client):
    response = client.get("/auth/me")
    assert response.status_code == 401


def test_protected_route_uses_current_user(client):
    assert client.get("/protected").status_code == 401
    signup(client)
    # Signup auto-logs-in: the fresh cookie authenticates immediately.
    response = client.get("/protected")
    assert response.status_code == 200
    assert response.json()["email"] == "u@example.com"


def test_signup_auto_login_sets_cookie(client, session_factory):
    response = signup(client)
    assert response.status_code == 200
    cookie = client.cookies.get("fastauth_session")
    assert cookie
    assert client.get("/auth/me").status_code == 200


async def test_logout_revokes_session_and_clears_cookie(client, session_factory):
    signup(client)
    login(client)
    cookie = client.cookies.get("fastauth_session")
    assert cookie

    response = client.post("/auth/logout")
    assert response.status_code == 200
    assert client.cookies.get("fastauth_session") is None

    # Replaying the revoked cookie is rejected…
    response = client.get("/auth/me", headers={"Cookie": f"fastauth_session={cookie}"})
    assert response.status_code == 401
    # …and the row is gone from the database.
    async with session_factory() as session:
        rows = (await session.execute(select(Session))).scalars().all()
        assert rows == []


def test_login_rotates_existing_session(client):
    """Second login kills the first session (fixation defense)."""
    signup(client)
    login(client)
    old_cookie = client.cookies.get("fastauth_session")

    login(client)
    new_cookie = client.cookies.get("fastauth_session")
    assert new_cookie and new_cookie != old_cookie

    response = client.get("/auth/me", headers={"Cookie": f"fastauth_session={old_cookie}"})
    assert response.status_code == 401
    assert client.get("/auth/me").status_code == 200


async def test_session_persists_exactly_one_row_per_login(client, session_factory):
    signup(client)
    login(client)
    async with session_factory() as session:
        assert len((await session.execute(select(Session))).scalars().all()) == 1
    login(client)
    async with session_factory() as session:
        # Rotation, not accumulation.
        assert len((await session.execute(select(Session))).scalars().all()) == 1
