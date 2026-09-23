"""Security: hooks must fail closed under adversarial conditions.

Attackers don't write hook handlers — but bugs do happen, and hook code
runs inside the auth trust boundary. These tests prove that no handler
misbehavior leaks internals, changes security decisions, or creates
distinguishable oracles.
"""

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from fastauth import JWTAuth, SessionAuth
from fastauth.adapters.sqlalchemy import SQLAlchemyJWTAdapter, SQLAlchemySessionAdapter
from tests.conftest import ExtraUser, RefreshToken, Session


def build_apps(get_db, config, jwt_config=None):
    """Session + JWT apps over ExtraUser (hook-mutable `role` field)."""
    s_auth = SessionAuth(
        adapter=SQLAlchemySessionAdapter,
        user_model=ExtraUser,
        session_model=Session,
        db_session_dependency=get_db,
        config=config,
    )
    j_config = config.model_copy(update={"jwt": jwt_config}) if jwt_config else config
    j_auth = JWTAuth(
        adapter=SQLAlchemyJWTAdapter,
        user_model=ExtraUser,
        refresh_model=RefreshToken,
        db_session_dependency=get_db,
        config=j_config,
    )
    s_app, j_app = FastAPI(), FastAPI()
    s_app.include_router(s_auth.router)
    j_app.include_router(j_auth.router)
    return (s_app, s_auth), (j_app, j_auth)


SIGNUP = {
    "email": "u@example.com",
    "password": "long-enough",
    "role": "member",
    "bio": "hi",
}
LOGIN = {"email": "u@example.com", "password": "long-enough"}


@pytest.fixture
def apps(get_db, test_config, jwt_config):
    return build_apps(get_db, test_config, jwt_config)


@pytest.mark.parametrize("route", ["/auth/signup", "/auth/login"])
def test_handler_crash_body_is_exactly_generic_session(apps, route):
    """A crashing before-hook must not leak tracebacks, emails, or secrets."""
    (s_app, s_auth), _ = apps

    async def boom(payload, request):
        raise RuntimeError("kaboom with u@example.com and long-enough")

    if "signup" in route:
        s_auth.on_before_signup(boom)
        body = dict(SIGNUP)
    else:
        s_auth.on_before_login(boom)
        with TestClient(s_app) as setup:
            setup.post("/auth/signup", json=SIGNUP)
        body = dict(LOGIN)
    with TestClient(s_app) as client:
        response = client.post(route, json=body)
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal error"}


@pytest.mark.parametrize("route", ["/auth/signup", "/auth/login"])
def test_handler_crash_body_is_exactly_generic_jwt(apps, route):
    """Same guarantee on the JWT strategy."""
    _, (j_app, j_auth) = apps

    async def boom(payload, request):
        raise RuntimeError("kaboom with u@example.com and long-enough")

    if "signup" in route:
        j_auth.on_before_signup(boom)
        body = dict(SIGNUP)
    else:
        j_auth.on_before_login(boom)
        with TestClient(j_app) as c:
            c.post("/auth/signup", json=SIGNUP)
        body = dict(LOGIN)
    with TestClient(j_app) as client:
        response = client.post(route, json=body)
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal error"}


def test_observer_return_value_cannot_change_response(apps):
    """Observers are fire-and-forget: even a truthy return is ignored."""
    (s_app, s_auth), _ = apps

    async def lying_observer(user, request):
        return {"admin": True, "detail": "pwned"}

    s_auth.on_after_signup(lying_observer)
    s_auth.on_after_login(lying_observer)
    with TestClient(s_app) as client:
        signup = client.post("/auth/signup", json=SIGNUP)
        assert signup.status_code == 200
        assert signup.json()["role"] == "member"
        assert "admin" not in signup.json()
        login = client.post("/auth/login", json=LOGIN)
        assert login.status_code == 200
        assert login.json() == {"success": True, "message": "Logged in successfully"}


@pytest.mark.parametrize(
    "email,password",
    [
        ("ghost@example.com", "long-enough"),  # unknown account
        ("u@example.com", "wrong-pass-1"),  # known account, wrong password
    ],
)
def test_login_failures_byte_identical_session(apps, email, password):
    """Unknown vs wrong-password must be indistinguishable on the wire."""
    (s_app, _), _ = apps
    with TestClient(s_app) as client:
        client.post("/auth/signup", json=SIGNUP)
        response = client.post(
            "/auth/login", json={"email": email, "password": password}
        )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials."}


@pytest.mark.parametrize(
    "email,password",
    [
        ("ghost@example.com", "long-enough"),
        ("u@example.com", "wrong-pass-1"),
    ],
)
def test_login_failures_byte_identical_jwt(apps, email, password):
    """Same indistinguishability guarantee on the JWT strategy."""
    _, (j_app, _) = apps
    with TestClient(j_app) as client:
        client.post("/auth/signup", json=SIGNUP)
        response = client.post(
            "/auth/login", json={"email": email, "password": password}
        )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials."}


async def test_hook_cannot_smuggle_non_schema_fields(apps, session_factory):
    """A handler assigning undeclared attributes (is_active, id,
    hashed_password) blows up inside the runner → 500, no user row."""
    (s_app, s_auth), _ = apps

    async def smuggle(payload, request):
        payload.is_active = False  # type: ignore[attr-defined]
        return payload

    s_auth.on_before_signup(smuggle)
    with TestClient(s_app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 500
    async with session_factory() as session:
        rows = (await session.execute(select(ExtraUser))).scalars().all()
        assert rows == []


async def test_deleted_user_refresh_token_is_401(apps, session_factory):
    """Token for a deleted account: 401, no crash, no resurrection."""
    from sqlalchemy import delete as sa_delete

    _, (j_app, _) = apps
    with TestClient(j_app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        login = client.post("/auth/login", json=LOGIN)
        assert login.status_code == 200
        access = login.json()["access_token"]
        assert (
            client.get(
                "/auth/me", headers={"Authorization": f"Bearer {access}"}
            ).status_code
            == 200
        )
        async with session_factory() as session:
            await session.execute(sa_delete(ExtraUser))
            await session.commit()
        assert (
            client.get(
                "/auth/me", headers={"Authorization": f"Bearer {access}"}
            ).status_code
            == 401
        )
