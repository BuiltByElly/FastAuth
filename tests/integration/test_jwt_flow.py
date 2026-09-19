"""Integration: full JWT-strategy lifecycle over HTTP."""

import uuid

import pytest
from sqlalchemy import func, select

from tests.conftest import RefreshToken, User, build_jwt_app, cookie_value


@pytest.fixture
def app_pair(get_db, test_config, jwt_config):
    """JWT app + auth instance (rate limiting disabled)."""
    config = test_config.model_copy(update={"jwt": jwt_config})
    return build_jwt_app(get_db, config=config)


@pytest.fixture
def client(app_pair):
    app, _ = app_pair
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        yield client


@pytest.fixture
def auth(app_pair):
    _, auth = app_pair
    return auth


def signup(client, email="u@example.com", password="long-enough"):
    return client.post("/auth/signup", json={"email": email, "password": password})


def login(client, email="u@example.com", password="long-enough"):
    return client.post("/auth/login", json={"email": email, "password": password})


def refresh(client, token):
    client.cookies.clear()
    return client.post("/auth/refresh", headers={"Cookie": f"fastauth_refresh={token}"})


def test_signup_issues_token_pair_and_auto_login(client):
    response = signup(client)
    assert response.status_code == 200
    body = response.json()
    assert len(body["access_token"].split(".")) == 3  # real JWT shape
    set_cookie = response.headers["set-cookie"]
    assert "fastauth_refresh=" in set_cookie
    assert len(cookie_value(set_cookie).split(".")) == 3
    # Immediately authenticated: no separate login needed.
    me = client.get(
        "/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"}
    )
    assert me.status_code == 200


def test_login_issues_fresh_pair(client):
    signup(client)
    response = login(client)
    assert response.status_code == 200
    assert len(response.json()["access_token"].split(".")) == 3
    assert "fastauth_refresh=" in response.headers["set-cookie"]


def test_signup_rejects_duplicate_email(client):
    assert signup(client).status_code == 200
    response = signup(client)
    assert response.status_code == 400
    assert response.json()["detail"] == "Email already registered."


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
    assert login(client).status_code == 403


async def test_inactive_user_token_rejected(client, session_factory):
    signup(client)
    token = login(client).json()["access_token"]
    async with session_factory() as session:
        user = (await session.execute(select(User))).scalar_one()
        user.is_active = False
        await session.commit()
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


def test_me_without_or_with_bad_bearer_is_401(client):
    assert client.get("/auth/me").status_code == 401
    assert client.get("/auth/me", headers={"Authorization": "Bearer garbage"}).status_code == 401


def test_protected_route_uses_current_user(client):
    assert client.get("/protected").status_code == 401
    signup(client)
    # Signup auto-logs-in: the fresh token authenticates immediately.
    token = login(client).json()["access_token"]
    response = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_refresh_rotates_pair(client):
    signup(client)
    first = login(client)
    refresh1 = cookie_value(first.headers["set-cookie"])

    second = refresh(client, refresh1)
    assert second.status_code == 200
    access2 = second.json()["access_token"]
    refresh2 = cookie_value(second.headers["set-cookie"])
    assert refresh2 != refresh1

    # New access token works.
    assert client.get("/auth/me", headers={"Authorization": f"Bearer {access2}"}).status_code == 200
    # Old refresh token is single-use: replay is rejected…
    assert refresh(client, refresh1).status_code == 401
    # …and the replay burned the whole family (reuse defense).
    assert refresh(client, refresh2).status_code == 401


def test_refresh_without_cookie_is_401(client):
    assert client.post("/auth/refresh").status_code == 401


def test_refresh_with_garbage_is_401(client):
    assert refresh(client, "not-a-token").status_code == 401


def test_logout_kills_refresh_token(client):
    signup(client)
    token = cookie_value(login(client).headers["set-cookie"])
    response = client.post("/auth/logout", headers={"Cookie": f"fastauth_refresh={token}"})
    assert response.status_code == 200
    assert client.cookies.get("fastauth_refresh") is None
    assert refresh(client, token).status_code == 401


def test_logout_without_cookie_is_401(client):
    assert client.post("/auth/logout").status_code == 401


async def test_inactive_user_token_rejected(client, session_factory):
    signup(client)
    token = login(client).json()["access_token"]
    async with session_factory() as session:
        user = (await session.execute(select(User))).scalar_one()
        user.is_active = False
        await session.commit()
    response = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401


async def test_purge_deletes_only_expired_rows(auth, session_factory, client):
    from datetime import UTC, datetime, timedelta

    signup(client)
    login(client)
    # Expire every outstanding row behind the tokens' backs (row/token skew).
    async with session_factory() as session:
        rows = (await session.execute(select(RefreshToken))).scalars().all()
        assert len(rows) == 2  # signup pair + login pair
        for row in rows:
            row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()

    async with session_factory() as session:
        deleted = await auth.purge_expired_refresh_tokens(session)
        await session.commit()
    assert deleted == 2
    async with session_factory() as session:
        remaining = await session.scalar(
            select(func.count()).select_from(RefreshToken)
        )
        assert remaining == 0
    # Purging again is a no-op returning 0.
    async with session_factory() as session:
        assert await auth.purge_expired_refresh_tokens(session) == 0


async def test_purge_keeps_outstanding_rows(auth, session_factory, client):
    signup(client)
    login(client)
    async with session_factory() as session:
        assert await auth.purge_expired_refresh_tokens(session) == 0
        remaining = await session.scalar(
            select(func.count()).select_from(RefreshToken)
        )
        assert remaining == 2  # signup pair + login pair, both outstanding


def test_jwt_requires_config(get_db):
    from fastauth import JWTAuth
    from fastauth.adapters import SQLAlchemyJWTAdapter

    from tests.conftest import RefreshToken, User

    with pytest.raises(ValueError, match="config.jwt"):
        JWTAuth(
            adapter=SQLAlchemyJWTAdapter,
            user_model=User,
            refresh_model=RefreshToken,
            db_session_dependency=get_db,
        )
