"""Integration: password-reset flow on both strategies.

Covers the two new hooks (`on_password_reset_requested`,
`on_password_changed`) plus the /forgot-password and /reset-password
routes: enumeration resistance, single-use tokens, expiry, session/JWT
revocation, and observer crash isolation.
"""

from datetime import UTC, datetime, timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select

from tests.conftest import build_jwt_app


def signup(client, email="u@example.com", password="long-enough"):
    return client.post("/auth/signup", json={"email": email, "password": password})


def login(client, email="u@example.com", password="long-enough"):
    return client.post("/auth/login", json={"email": email, "password": password})


def forgot(client, email="u@example.com"):
    return client.post("/auth/forgot-password", json={"email": email})


def reset(client, token, new_password="brand-new-password"):
    return client.post(
        "/auth/reset-password",
        json={"token": token, "new_password": new_password},
    )


# ---------- shared contract (session strategy via fixture) ----------


def test_forgot_unknown_and_known_are_identical(session_client):
    """No oracle: same status + body whether the email exists or not."""
    session_client.post(
        "/auth/signup", json={"email": "u@example.com", "password": "long-enough"}
    )
    known = forgot(session_client, "u@example.com")
    unknown = forgot(session_client, "ghost@example.com")
    assert known.status_code == 200
    assert unknown.status_code == 200
    assert known.json() == unknown.json() == {
        "detail": "If that email exists, a reset link was sent."
    }


async def test_reset_requested_hook_fires_session(get_db, test_config, session_factory):
    from fastapi import FastAPI

    from fastauth import SessionAuth
    from fastauth.adapters.sqlalchemy import SQLAlchemySessionAdapter
    from tests.conftest import PasswordResetToken as PRT
    from tests.conftest import Session as S
    from tests.conftest import User as U

    seen = []
    auth = SessionAuth(
        adapter=SQLAlchemySessionAdapter,
        user_model=U,
        session_model=S,
        password_reset_token_model=PRT,
        db_session_dependency=get_db,
        config=test_config,
    )

    @auth.on_password_reset_requested
    async def record(event, request):
        seen.append(event)

    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app) as client:
        assert signup(client).status_code == 200
        assert forgot(client).status_code == 200
    assert len(seen) == 1
    assert seen[0].email == "u@example.com"
    assert seen[0].token
    # The stored row holds only the hash, never the raw token.
    async with session_factory() as session:
        row = (await session.execute(select(PRT))).scalar_one()
        assert row.token_hash != seen[0].token
        assert row.used_at is None


async def test_password_changed_hook_fires_session(
    get_db, test_config, session_factory
):
    from fastapi import FastAPI

    from fastauth import SessionAuth
    from fastauth.adapters.sqlalchemy import SQLAlchemySessionAdapter
    from tests.conftest import PasswordResetToken as PRT
    from tests.conftest import Session as S
    from tests.conftest import User as U

    requested, changed = [], []
    auth = SessionAuth(
        adapter=SQLAlchemySessionAdapter,
        user_model=U,
        session_model=S,
        password_reset_token_model=PRT,
        db_session_dependency=get_db,
        config=test_config,
    )

    @auth.on_password_reset_requested
    async def on_req(event, request):
        requested.append(event.token)

    @auth.on_password_changed
    async def on_changed(event, request):
        changed.append(event.user_id)

    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app) as client:
        assert signup(client).status_code == 200
        assert forgot(client).status_code == 200
        assert reset(client, requested[0]).status_code == 200
    assert len(changed) == 1
    async with session_factory() as session:
        user = (await session.execute(select(U))).scalar_one()
        assert changed[0] == str(user.id)


async def test_session_reset_revokes_other_sessions(
    get_db, test_config, session_factory
):
    """Reset kills every session row: other devices are logged out."""
    from fastapi import FastAPI

    from fastauth import SessionAuth
    from fastauth.adapters.sqlalchemy import SQLAlchemySessionAdapter
    from tests.conftest import PasswordResetToken as PRT
    from tests.conftest import Session as S
    from tests.conftest import User as U

    tokens = []
    auth = SessionAuth(
        adapter=SQLAlchemySessionAdapter,
        user_model=U,
        session_model=S,
        password_reset_token_model=PRT,
        db_session_dependency=get_db,
        config=test_config,
    )

    @auth.on_password_reset_requested
    async def cap(event, request):
        tokens.append(event.token)

    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app) as client:
        assert signup(client).status_code == 200
        victim_cookie = client.cookies.get("fastauth_session")
        assert forgot(client).status_code == 200
        assert reset(client, tokens[0]).status_code == 200
        # Old cookie dead…
        client.cookies.clear()
        assert (
            client.get(
                "/auth/me",
                headers={"Cookie": f"fastauth_session={victim_cookie}"},
            ).status_code
            == 401
        )
        # …and the new password works.
        assert login(client, password="brand-new-password").status_code == 200
        assert login(client, password="long-enough").status_code == 401
    async with session_factory() as session:
        rows = (await session.execute(select(S))).scalars().all()
        # Only the post-reset login session survives.
        assert len(rows) == 1


async def test_session_reset_single_use_and_unknown(get_db, test_config):
    from fastapi import FastAPI

    from fastauth import SessionAuth
    from fastauth.adapters.sqlalchemy import SQLAlchemySessionAdapter
    from tests.conftest import PasswordResetToken as PRT
    from tests.conftest import Session as S
    from tests.conftest import User as U

    tokens = []
    auth = SessionAuth(
        adapter=SQLAlchemySessionAdapter,
        user_model=U,
        session_model=S,
        password_reset_token_model=PRT,
        db_session_dependency=get_db,
        config=test_config,
    )

    @auth.on_password_reset_requested
    async def cap(event, request):
        tokens.append(event.token)

    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app) as client:
        assert signup(client).status_code == 200
        assert forgot(client).status_code == 200
        assert reset(client, tokens[0]).status_code == 200
        # Replay burns: same token is now invalid.
        replay = reset(client, tokens[0])
        assert replay.status_code == 400
        assert replay.json() == {"detail": "Invalid or expired token."}
        # Garbage is the same 400 (no oracle).
        garbage = reset(client, "not-a-real-token")
        assert garbage.status_code == 400
        assert garbage.json() == {"detail": "Invalid or expired token."}


async def test_session_reset_expired_token_rejected(get_db, test_config, session_factory):
    from fastapi import FastAPI

    from fastauth import SessionAuth
    from fastauth.adapters.sqlalchemy import SQLAlchemySessionAdapter
    from tests.conftest import PasswordResetToken as PRT
    from tests.conftest import Session as S
    from tests.conftest import User as U

    tokens = []
    auth = SessionAuth(
        adapter=SQLAlchemySessionAdapter,
        user_model=U,
        session_model=S,
        password_reset_token_model=PRT,
        db_session_dependency=get_db,
        config=test_config,
    )

    @auth.on_password_reset_requested
    async def cap(event, request):
        tokens.append(event.token)

    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app) as client:
        assert signup(client).status_code == 200
        assert forgot(client).status_code == 200
    async with session_factory() as session:
        row = (await session.execute(select(PRT))).scalar_one()
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    with TestClient(app) as client:
        response = reset(client, tokens[0])
        assert response.status_code == 400
        assert response.json() == {"detail": "Invalid or expired token."}


async def test_password_hooks_crash_ignored(get_db, test_config):
    """A crashing password hook must not break the reset flow."""
    from fastapi import FastAPI

    from fastauth import SessionAuth
    from fastauth.adapters.sqlalchemy import SQLAlchemySessionAdapter
    from tests.conftest import PasswordResetToken as PRT
    from tests.conftest import Session as S
    from tests.conftest import User as U

    tokens = []
    auth = SessionAuth(
        adapter=SQLAlchemySessionAdapter,
        user_model=U,
        session_model=S,
        password_reset_token_model=PRT,
        db_session_dependency=get_db,
        config=test_config,
    )

    @auth.on_password_reset_requested
    async def boom_req(event, request):
        raise RuntimeError("kaboom")

    @auth.on_password_changed
    async def boom_changed(event, request):
        raise RuntimeError("kaboom")

    @auth.on_password_reset_requested
    async def cap(event, request):
        tokens.append(event.token)

    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app) as client:
        assert signup(client).status_code == 200
        assert forgot(client).status_code == 200
        # Even though the first requested-handler crashed, the second ran.
        assert tokens
        assert reset(client, tokens[0]).status_code == 200


def test_reset_rejects_short_password(session_client):
    response = session_client.post(
        "/auth/reset-password",
        json={"token": "anything", "new_password": "short"},
    )
    assert response.status_code == 422


# ---------- JWT strategy ----------


async def test_jwt_hooks_and_access_token_invalidation(
    get_db, test_config, jwt_config, session_factory
):
    """Reset revokes the refresh family and kills outstanding access tokens."""
    from fastapi import FastAPI

    from fastauth import JWTAuth
    from fastauth.adapters.sqlalchemy import SQLAlchemyJWTAdapter
    from tests.conftest import PasswordResetToken as PRT
    from tests.conftest import RefreshToken as RT
    from tests.conftest import User as U
    from tests.conftest import cookie_value

    tokens = []
    config = test_config.model_copy(update={"jwt": jwt_config})
    auth = JWTAuth(
        adapter=SQLAlchemyJWTAdapter,
        user_model=U,
        refresh_model=RT,
        password_reset_token_model=PRT,
        db_session_dependency=get_db,
        config=config,
    )

    @auth.on_password_reset_requested
    async def cap(event, request):
        tokens.append(event.token)

    changed = []

    @auth.on_password_changed
    async def on_changed(event, request):
        changed.append(event.user_id)

    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app) as client:
        assert signup(client).status_code == 200
        old_access = login(client).json()["access_token"]
        old_refresh = cookie_value(login(client).headers["set-cookie"])
        assert forgot(client).status_code == 200
        assert reset(client, tokens[0]).status_code == 200
        assert len(changed) == 1
        # Old access token is dead (password_changed_at invalidated it)…
        assert (
            client.get(
                "/auth/me", headers={"Authorization": f"Bearer {old_access}"}
            ).status_code
            == 401
        )
        # …old refresh tokens can't mint replacements…
        client.cookies.clear()
        assert (
            client.post(
                "/auth/refresh",
                headers={"Cookie": f"fastauth_refresh={old_refresh}"},
            ).status_code
            == 401
        )
        # …but the new password logs in fine.
        assert login(client, password="brand-new-password").status_code == 200


async def test_jwt_forgot_unknown_is_identical(get_db, test_config, jwt_config):
    config = test_config.model_copy(update={"jwt": jwt_config})
    app, _ = build_jwt_app(get_db, config=config)
    with TestClient(app) as client:
        assert signup(client).status_code == 200
        known = forgot(client, "u@example.com")
        unknown = forgot(client, "ghost@example.com")
        assert known.json() == unknown.json() == {
            "detail": "If that email exists, a reset link was sent."
        }


async def test_jwt_reset_single_use(get_db, test_config, jwt_config):
    from fastapi import FastAPI

    from fastauth import JWTAuth
    from fastauth.adapters.sqlalchemy import SQLAlchemyJWTAdapter
    from tests.conftest import PasswordResetToken as PRT
    from tests.conftest import RefreshToken as RT
    from tests.conftest import User as U

    tokens = []
    config = test_config.model_copy(update={"jwt": jwt_config})
    auth = JWTAuth(
        adapter=SQLAlchemyJWTAdapter,
        user_model=U,
        refresh_model=RT,
        password_reset_token_model=PRT,
        db_session_dependency=get_db,
        config=config,
    )

    @auth.on_password_reset_requested
    async def cap(event, request):
        tokens.append(event.token)

    app = FastAPI()
    app.include_router(auth.router)
    with TestClient(app) as client:
        assert signup(client).status_code == 200
        assert forgot(client).status_code == 200
        assert reset(client, tokens[0]).status_code == 200
        assert reset(client, tokens[0]).status_code == 400
