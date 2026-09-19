"""Security: session tokens must be unguessable, expirable, and revocable."""

import uuid
from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from tests.conftest import Session, User


def _me(client, cookie):
    client.cookies.clear()
    if cookie is None:
        return client.get("/auth/me")
    return client.get("/auth/me", headers={"Cookie": f"fastauth_session={cookie}"})


def test_random_uuid_session_rejected(session_client):
    assert _me(session_client, str(uuid.uuid4())).status_code == 401


def test_garbage_session_rejected(session_client):
    for bad in ("", "garbage", "123", "null", "undefined", "0" * 36):
        assert _me(session_client, bad).status_code == 401


def test_missing_cookie_rejected(session_client):
    assert _me(session_client, None).status_code == 401


async def test_expired_session_rejected(session_client, session_factory):
    session_client.post(
        "/auth/signup", json={"email": "u@example.com", "password": "long-enough"}
    )
    cookie = session_client.cookies.get("fastauth_session")
    async with session_factory() as session:
        row = (await session.execute(select(Session))).scalar_one()
        row.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await session.commit()
    assert _me(session_client, cookie).status_code == 401


async def test_inactive_user_session_rejected(session_client, session_factory):
    session_client.post(
        "/auth/signup", json={"email": "u@example.com", "password": "long-enough"}
    )
    cookie = session_client.cookies.get("fastauth_session")
    async with session_factory() as session:
        user = (await session.execute(select(User))).scalar_one()
        user.is_active = False
        await session.commit()
    assert _me(session_client, cookie).status_code == 401


def test_logged_out_session_cannot_be_replayed(session_client):
    session_client.post(
        "/auth/signup", json={"email": "u@example.com", "password": "long-enough"}
    )
    cookie = session_client.cookies.get("fastauth_session")
    assert session_client.post("/auth/logout").status_code == 200
    assert _me(session_client, cookie).status_code == 401


def test_attacker_prefixed_session_is_rotated_away(session_client):
    """An attacker-planted pre-login session id dies at the login boundary."""
    session_client.post(
        "/auth/signup", json={"email": "u@example.com", "password": "long-enough"}
    )
    victim_cookie = session_client.cookies.get("fastauth_session")
    # Attacker tricks the victim into adopting a known session id…
    planted = str(uuid.uuid4())
    session_client.cookies.clear()
    # …but the next login burns whatever came in and issues a fresh id.
    session_client.post(
        "/auth/login",
        json={"email": "u@example.com", "password": "long-enough"},
        headers={"Cookie": f"fastauth_session={planted}"},
    )
    fresh = session_client.cookies.get("fastauth_session")
    assert fresh not in (victim_cookie, planted)
    # The planted id never becomes a live session…
    assert _me(session_client, planted).status_code == 401
    # …while the victim's other legitimate session is untouched (rotation
    # burns only the presented token — multi-device sessions keep working).
    assert _me(session_client, victim_cookie).status_code == 200
    assert _me(session_client, fresh).status_code == 200
