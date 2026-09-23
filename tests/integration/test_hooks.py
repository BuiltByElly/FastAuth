"""Integration: hook contracts on both strategies.

Covers all four hook families — signup (before/after/failure), login
(before/failure/after), logout (after), refresh reuse — asserting what each
handler receives, what the client sees, and what lands in the database.
"""

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from fastauth import JWTAuth, SessionAuth
from fastauth.adapters.sqlalchemy import SQLAlchemyJWTAdapter, SQLAlchemySessionAdapter
from fastauth.hooks.exceptions import HookAbort
from fastauth.hooks.login import LoginFailure
from tests.conftest import ExtraUser, RefreshToken, Session

SIGNUP = {
    "email": "u@example.com",
    "password": "long-enough",
    "role": "member",
    "bio": "hello",
}


def extra_session_app(get_db, config):
    auth = SessionAuth(
        adapter=SQLAlchemySessionAdapter,
        user_model=ExtraUser,
        session_model=Session,
        db_session_dependency=get_db,
        config=config,
    )
    app = FastAPI()
    app.include_router(auth.router)
    return app, auth


def extra_jwt_app(get_db, config):
    auth = JWTAuth(
        adapter=SQLAlchemyJWTAdapter,
        user_model=ExtraUser,
        refresh_model=RefreshToken,
        db_session_dependency=get_db,
        config=config,
    )
    app = FastAPI()
    app.include_router(auth.router)
    return app, auth


def jwt_configured(test_config, jwt_config):
    return test_config.model_copy(update={"jwt": jwt_config})


async def extra_user_count(session_factory):
    async with session_factory() as session:
        return await session.scalar(select(func.count()).select_from(ExtraUser))


async def extra_user_row(session_factory):
    async with session_factory() as session:
        return (await session.execute(select(ExtraUser))).scalar_one()


# ---------- signup: before ----------


async def test_before_signup_mutation_reaches_db_and_response(
    get_db, test_config, session_factory
):
    seen = {}

    async def upper(payload, request):
        payload.role = payload.role.upper()
        seen["role"] = payload.role
        return payload

    app, auth = extra_session_app(get_db, test_config)
    auth.on_before_signup(upper)
    with TestClient(app) as client:
        response = client.post("/auth/signup", json=SIGNUP)
    assert response.status_code == 200
    assert response.json()["role"] == "MEMBER"
    assert seen["role"] == "MEMBER"
    row = await extra_user_row(session_factory)
    assert row.role == "MEMBER"
    assert row.bio == "hello"


async def test_before_signup_abort_returns_custom_status(
    get_db, test_config, session_factory
):
    async def deny(payload, request):
        raise HookAbort(403, "Denied")

    app, auth = extra_session_app(get_db, test_config)
    auth.on_before_signup(deny)
    with TestClient(app) as client:
        response = client.post("/auth/signup", json=SIGNUP)
    assert response.status_code == 403
    assert response.json() == {"detail": "Denied"}
    assert await extra_user_count(session_factory) == 0


async def test_before_signup_crash_is_generic_500(get_db, test_config, session_factory):
    async def boom(payload, request):
        raise RuntimeError("kaboom")

    app, auth = extra_session_app(get_db, test_config)
    auth.on_before_signup(boom)
    with TestClient(app) as client:
        response = client.post("/auth/signup", json=SIGNUP)
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal error"}
    assert await extra_user_count(session_factory) == 0


async def test_before_signup_wrong_return_type_is_500(
    get_db, test_config, session_factory
):
    async def sloppy(payload, request):
        return {"email": "x@y.zz", "password": "long-enough", "role": "m"}

    app, auth = extra_session_app(get_db, test_config)
    auth.on_before_signup(sloppy)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 500
    assert await extra_user_count(session_factory) == 0


# ---------- signup: observers ----------


async def test_after_signup_observer_fires(get_db, test_config):
    seen = {}

    async def record(user, request):
        seen["email"] = user.email
        seen["path"] = request.url.path

    app, auth = extra_session_app(get_db, test_config)
    auth.on_after_signup(record)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
    assert seen == {"email": "u@example.com", "path": "/auth/signup"}


async def test_after_signup_observer_crash_ignored(get_db, test_config):
    async def boom(user, request):
        raise RuntimeError("kaboom")

    app, auth = extra_session_app(get_db, test_config)
    auth.on_after_signup(boom)
    with TestClient(app) as client:
        response = client.post("/auth/signup", json=SIGNUP)
    assert response.status_code == 200
    assert response.json()["role"] == "member"


async def test_signup_failure_observer_on_duplicate(get_db, test_config):
    seen = []

    async def record(error, request):
        seen.append(error)

    app, auth = extra_session_app(get_db, test_config)
    auth.on_signup_failure(record)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        response = client.post("/auth/signup", json=SIGNUP)
    assert response.status_code == 400
    assert response.json() == {"detail": "Email already registered"}
    assert seen == ["User's email already exists"]


async def test_signup_failure_observer_crash_ignored(get_db, test_config):
    async def boom(error, request):
        raise RuntimeError("kaboom")

    app, auth = extra_session_app(get_db, test_config)
    auth.on_signup_failure(boom)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        assert client.post("/auth/signup", json=SIGNUP).status_code == 400


# ---------- login ----------


async def test_before_login_abort_blocks_without_session(
    get_db, test_config, session_factory
):
    async def deny(payload, request):
        raise HookAbort(429, "Slow down")

    app, auth = extra_session_app(get_db, test_config)
    auth.on_before_login(deny)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        response = client.post(
            "/auth/login",
            json={"email": "u@example.com", "password": "long-enough"},
        )
    assert response.status_code == 429
    assert response.json() == {"detail": "Slow down"}
    async with session_factory() as session:
        rows = (await session.execute(select(Session))).scalars().all()
        # Signup's own session only — the aborted login created nothing.
        assert len(rows) == 1


async def test_before_login_can_normalize_email(get_db, test_config):
    async def lower(payload, request):
        payload.email = payload.email.lower()
        return payload

    app, auth = extra_session_app(get_db, test_config)
    auth.on_before_login(lower)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        response = client.post(
            "/auth/login",
            json={"email": "U@EXAMPLE.COM", "password": "long-enough"},
        )
    assert response.status_code == 200


async def test_login_failure_unknown_user_reports_none(get_db, test_config):
    seen = []

    async def record(failure, request):
        seen.append(failure)

    app, auth = extra_session_app(get_db, test_config)
    auth.on_login_failure(record)
    with TestClient(app) as client:
        response = client.post(
            "/auth/login",
            json={"email": "ghost@example.com", "password": "long-enough"},
        )
    assert response.status_code == 401
    assert len(seen) == 1
    assert isinstance(seen[0], LoginFailure)
    assert seen[0].user_id is None
    assert seen[0].error == "User not found"


async def test_login_failure_wrong_password_hides_user_id(get_db, test_config):
    seen = []

    async def record(failure, request):
        seen.append(failure)

    app, auth = extra_session_app(get_db, test_config)
    auth.on_login_failure(record)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        response = client.post(
            "/auth/login",
            json={"email": "u@example.com", "password": "wrong-pass-1"},
        )
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials."}
    assert len(seen) == 1
    # Even though the account exists, observers must not learn that.
    assert seen[0].user_id is None
    assert seen[0].error == "Invalid credentials."


async def test_login_failure_inactive_reports_real_id(
    get_db, test_config, session_factory
):
    seen = []

    async def record(failure, request):
        seen.append(failure)

    app, auth = extra_session_app(get_db, test_config)
    auth.on_login_failure(record)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        async with session_factory() as session:
            user = (await session.execute(select(ExtraUser))).scalar_one()
            user.is_active = False
            await session.commit()
            user_id = str(user.id)
        response = client.post(
            "/auth/login",
            json={"email": "u@example.com", "password": "long-enough"},
        )
    assert response.status_code == 403
    assert len(seen) == 1
    assert seen[0].user_id == user_id
    assert seen[0].error == "Account is inactive."


async def test_after_login_fires_on_success(get_db, test_config):
    seen = {}

    async def record(user, request):
        seen["email"] = user.email
        seen["path"] = request.url.path

    app, auth = extra_session_app(get_db, test_config)
    auth.on_after_login(record)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        assert (
            client.post(
                "/auth/login",
                json={"email": "u@example.com", "password": "long-enough"},
            ).status_code
            == 200
        )
    assert seen == {"email": "u@example.com", "path": "/auth/login"}


async def test_after_login_crash_ignored(get_db, test_config):
    async def boom(user, request):
        raise RuntimeError("kaboom")

    app, auth = extra_session_app(get_db, test_config)
    auth.on_after_login(boom)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        response = client.post(
            "/auth/login",
            json={"email": "u@example.com", "password": "long-enough"},
        )
    assert response.status_code == 200
    assert response.json()["success"] is True


# ---------- logout ----------


async def test_after_logout_receives_user_id(get_db, test_config, session_factory):
    seen = []

    async def record(user_id):
        seen.append(user_id)

    app, auth = extra_session_app(get_db, test_config)
    auth.on_after_logout(record)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        async with session_factory() as session:
            user = (await session.execute(select(ExtraUser))).scalar_one()
            user_id = str(user.id)
        assert client.post("/auth/logout").status_code == 200
    assert seen == [user_id]


async def test_after_logout_not_fired_for_unknown_token(get_db, test_config):
    seen = []

    async def record(user_id):
        seen.append(user_id)

    app, auth = extra_session_app(get_db, test_config)
    auth.on_after_logout(record)
    with TestClient(app) as client:
        # Logout is idempotent: unknown token still returns success…
        response = client.post(
            "/auth/logout", headers={"Cookie": "fastauth_session=deadbeef"}
        )
    assert response.status_code == 200
    # …but no user was resolved, so the hook never fires.
    assert seen == []


async def test_after_logout_crash_ignored(get_db, test_config):
    async def boom(user_id):
        raise RuntimeError("kaboom")

    app, auth = extra_session_app(get_db, test_config)
    auth.on_after_logout(boom)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        response = client.post("/auth/logout")
    assert response.status_code == 200
    assert response.json() == {"success": True, "message": "logged out"}


# ---------- JWT strategy ----------


async def test_jwt_before_signup_mutation(get_db, test_config, jwt_config):
    seen = {}

    async def upper(payload, request):
        payload.role = payload.role.upper()
        seen["role"] = payload.role
        return payload

    app, auth = extra_jwt_app(
        get_db, test_config.model_copy(update={"jwt": jwt_config})
    )
    auth.on_before_signup(upper)
    with TestClient(app) as client:
        response = client.post("/auth/signup", json=SIGNUP)
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert seen["role"] == "MEMBER"


async def test_jwt_before_signup_abort(get_db, test_config, jwt_config):
    async def deny(payload, request):
        raise HookAbort(403, "Denied")

    app, auth = extra_jwt_app(
        get_db, test_config.model_copy(update={"jwt": jwt_config})
    )
    auth.on_before_signup(deny)
    with TestClient(app) as client:
        response = client.post("/auth/signup", json=SIGNUP)
    assert response.status_code == 403
    assert response.json() == {"detail": "Denied"}


async def test_jwt_login_failure_hides_id(get_db, test_config, jwt_config):
    seen = []

    async def record(failure, request):
        seen.append(failure)

    app, auth = extra_jwt_app(
        get_db, test_config.model_copy(update={"jwt": jwt_config})
    )
    auth.on_login_failure(record)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        response = client.post(
            "/auth/login",
            json={"email": "u@example.com", "password": "wrong-pass-1"},
        )
    assert response.status_code == 401
    assert len(seen) == 1
    assert seen[0].user_id is None


async def test_jwt_after_logout_user_id(get_db, test_config, jwt_config):
    seen = []

    async def record(user_id):
        seen.append(user_id)

    app, auth = extra_jwt_app(
        get_db, test_config.model_copy(update={"jwt": jwt_config})
    )
    auth.on_after_logout(record)
    with TestClient(app) as client:
        assert client.post("/auth/signup", json=SIGNUP).status_code == 200
        response = client.post("/auth/logout")
    assert response.status_code == 200
    assert len(seen) == 1
    assert seen[0]


async def _jwt_login_refresh_pair(client):
    """Sign up + log in, returning (access_token, refresh_cookie)."""
    assert client.post("/auth/signup", json=SIGNUP).status_code == 200
    login = client.post(
        "/auth/login", json={"email": "u@example.com", "password": "long-enough"}
    )
    assert login.status_code == 200
    refresh = login.headers["set-cookie"].split(";")[0].split("=", 1)[1].strip('"')
    return login.json()["access_token"], refresh


async def _refresh(client, token):
    client.cookies.clear()
    return client.post("/auth/refresh", headers={"Cookie": f"fastauth_refresh={token}"})


async def test_reuse_hook_fires_with_user_id(
    get_db, test_config, jwt_config, session_factory
):
    seen = []

    async def record(user_id, request):
        seen.append((user_id, request.url.path))

    app, auth = extra_jwt_app(
        get_db, test_config.model_copy(update={"jwt": jwt_config})
    )
    auth.on_token_reuse_detected(record)
    with TestClient(app) as client:
        _, refresh1 = await _jwt_login_refresh_pair(client)
        second = await _refresh(client, refresh1)
        assert second.status_code == 200
        refresh2 = (
            second.headers["set-cookie"].split(";")[0].split("=", 1)[1].strip('"')
        )
        # Replay the burned token: 401 JSON, family revoked, hook fired.
        replay = await _refresh(client, refresh1)
        assert replay.status_code == 401
        assert replay.json() == {"detail": "Invalid or expired refresh token."}
        # The fresh sibling died with the family.
        assert (await _refresh(client, refresh2)).status_code == 401
    assert len(seen) == 1
    user_id, path = seen[0]
    async with session_factory() as session:
        row = (await session.execute(select(ExtraUser))).scalar_one()
        assert user_id == str(row.id)
    assert path == "/auth/refresh"


async def test_reuse_hook_crash_ignored(get_db, test_config, jwt_config):
    async def boom(user_id, request):
        raise RuntimeError("kaboom")

    app, auth = extra_jwt_app(
        get_db, test_config.model_copy(update={"jwt": jwt_config})
    )
    auth.on_token_reuse_detected(boom)
    with TestClient(app) as client:
        _, refresh1 = await _jwt_login_refresh_pair(client)
        assert (await _refresh(client, refresh1)).status_code == 200
        replay = await _refresh(client, refresh1)
    assert replay.status_code == 401
    assert replay.json() == {"detail": "Invalid or expired refresh token."}


async def test_reuse_storm_stays_401(get_db, test_config, jwt_config):
    seen = []

    async def record(user_id, request):
        seen.append(user_id)

    app, auth = extra_jwt_app(
        get_db, test_config.model_copy(update={"jwt": jwt_config})
    )
    auth.on_token_reuse_detected(record)
    with TestClient(app) as client:
        _, refresh1 = await _jwt_login_refresh_pair(client)
        assert (await _refresh(client, refresh1)).status_code == 200
        for _ in range(3):
            response = await _refresh(client, refresh1)
            assert response.status_code == 401
            assert response.json() == {"detail": "Invalid or expired refresh token."}
    # Fires exactly once (first replay revokes the family); later replays of
    # the now-revoked row are silent 401s — no alert-spam on replay storms.
    assert len(seen) == 1
