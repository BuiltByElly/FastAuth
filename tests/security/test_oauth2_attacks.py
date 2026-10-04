"""Security: OAuth2 state/CSRF hardening, deactivated accounts, claim abuse.

The provider is stubbed (`stub_oauth2_provider`) — every test exercises
FastAuth's own verification, never the network.

Deliberately narrower than `test_oidc_attacks.py`: both strategies share
`OAuthStateManager` and the same account-abuse guards, so the exhaustive
state edge cases (expiry, cross-provider binding) are not duplicated here —
only the core paths unique to the OAuth2 route (cookie name, redirect, token
handoff) plus fail-closed account handling and the route's own rate limits.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from fastauth.config import (
    CookieConfig,
    FastAuthConfig,
    RateLimitConfig,
)
from fastauth.security import verify_password
from tests.conftest import (
    OAuth2Account,
    User,
    build_oauth2_app,
    create_user,
    oauth2_begin,
    stub_oauth2_provider,
)

STATE_COOKIE = "fastauth_oauth2_state"
STATE_REJECTED = {"detail": "Invalid or expired state"}


def _callback(client, state, provider="github"):
    return client.get(f"/auth/oauth2/{provider}/callback?code=code&state={state}")


def _assert_rejected(response):
    """Same status, same body — no oracle for what went wrong."""
    assert response.status_code == 400
    assert response.json() == STATE_REJECTED


@pytest.fixture
def oauth2_app(get_db, oauth2_test_config, monkeypatch):
    """Session-strategy OAuth2 app with a stubbed provider (rate limiting off)."""
    stub_oauth2_provider(monkeypatch)
    return build_oauth2_app(get_db, config=oauth2_test_config)


@pytest.fixture
def client(oauth2_app):
    app, _ = oauth2_app
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


# --- login: redirect + state cookie hardening --------------------------------


def test_login_redirects_to_provider_with_fresh_state(client):
    response = client.get("/auth/oauth2/github/login")
    assert response.status_code == 307
    location = response.headers["location"]
    assert location.startswith("https://provider.example/authorize?")
    assert "state=" in location
    assert client.cookies.get(STATE_COOKIE)  # round-trips via cookie on callback


def test_state_cookie_flags_are_hardened(get_db, oauth2_config, monkeypatch):
    """Default (production) cookie flags, read off the raw header."""
    stub_oauth2_provider(monkeypatch)
    config = FastAuthConfig(
        cookies=CookieConfig(secure=True),
        rate_limit=RateLimitConfig(enabled=False),
        oauth2=oauth2_config,
    )
    app, _ = build_oauth2_app(get_db, config=config)
    with TestClient(app, follow_redirects=False) as client:
        response = client.get("/auth/oauth2/github/login")
    header = response.headers["set-cookie"]
    assert header.startswith(f"{STATE_COOKIE}=")
    assert "HttpOnly" in header  # no JS access → XSS can't steal it
    assert "Secure" in header  # HTTPS only
    assert "SameSite=lax" in header  # no cross-site sends
    assert "Max-Age=300" in header  # short-lived CSRF window
    assert "Path=/" in header


# --- callback: state verification --------------------------------------------


def test_callback_without_state_cookie_is_rejected(client):
    state = oauth2_begin(client)
    client.cookies.clear()
    _assert_rejected(_callback(client, state))


def test_callback_with_mismatched_state_is_rejected(client):
    state = oauth2_begin(client)
    assert state != "A" * 43
    _assert_rejected(_callback(client, "A" * 43))


def test_callback_with_forged_state_cookie_is_rejected(client):
    state = oauth2_begin(client)
    client.cookies.set(STATE_COOKIE, "forged.deadbeef")
    _assert_rejected(_callback(client, state))


def test_state_cannot_be_replayed(client):
    state = oauth2_begin(client)
    assert _callback(client, state).status_code == 200
    # First callback consumed the cookie — replay has nothing to verify.
    _assert_rejected(_callback(client, state))


def test_unknown_provider_is_404(client):
    assert client.get("/auth/oauth2/nope/login").status_code == 404
    assert client.get("/auth/oauth2/nope/callback?code=x&state=y").status_code == 404


# --- account abuse ------------------------------------------------------------


async def test_deactivated_account_cannot_sign_in_again(
    get_db, oauth2_test_config, monkeypatch, session_factory
):
    stub_oauth2_provider(monkeypatch)
    app, _ = build_oauth2_app(get_db, config=oauth2_test_config)
    with TestClient(app, follow_redirects=False) as client:
        assert _callback(client, oauth2_begin(client)).status_code == 200
        assert client.get("/protected").status_code == 200

        async with session_factory() as session:
            user = (await session.execute(select(User))).scalar_one()
            user.is_active = False
            await session.commit()

        client.cookies.clear()
        response = _callback(client, oauth2_begin(client))
        assert response.status_code == 403
        assert response.json() == {"detail": "Account is inactive."}
        assert client.cookies.get("fastauth_session") is None
        assert client.get("/protected").status_code == 401


async def test_provider_email_claim_cannot_take_over_password_account(
    get_db, oauth2_test_config, monkeypatch, session_factory
):
    await create_user(session_factory, email="u@example.com", password="long-enough")
    stub_oauth2_provider(monkeypatch, email="u@example.com")
    app, _ = build_oauth2_app(get_db, config=oauth2_test_config)
    with TestClient(app, follow_redirects=False) as client:
        response = _callback(client, oauth2_begin(client))
        assert response.status_code == 400
        assert response.json() == {"detail": "Email already registered"}
        assert client.cookies.get("fastauth_session") is None
        assert client.get("/protected").status_code == 401

    async with session_factory() as session:
        users = (await session.execute(select(User))).scalars().all()
        # Exactly the seeded account, still password-only, untouched.
        assert len(users) == 1
        assert verify_password("long-enough", users[0].hashed_password)
        assert (await session.execute(select(OAuth2Account))).scalars().all() == []


async def test_orphaned_account_row_fails_closed(
    get_db, oauth2_test_config, monkeypatch, session_factory
):
    """Account row whose user was deleted: no crash, no resurrection."""
    stub_oauth2_provider(monkeypatch)
    app, _ = build_oauth2_app(get_db, config=oauth2_test_config)
    with TestClient(app, follow_redirects=False) as client:
        assert _callback(client, oauth2_begin(client)).status_code == 200
        async with session_factory() as session:
            await session.execute(delete(User))
            await session.commit()

        client.cookies.clear()
        response = _callback(client, oauth2_begin(client))
        assert response.status_code == 401
        assert client.cookies.get("fastauth_session") is None

        async with session_factory() as session:
            assert (await session.execute(select(User))).scalars().all() == []
            accounts = (await session.execute(select(OAuth2Account))).scalars().all()
            assert len(accounts) == 1  # row remains, but grants nothing


# --- rate limiting ------------------------------------------------------------


def test_oauth2_login_is_rate_limited(get_db, oauth2_test_config, monkeypatch):
    stub_oauth2_provider(monkeypatch)
    config = oauth2_test_config.model_copy(update={"rate_limit": RateLimitConfig()})
    app, _ = build_oauth2_app(get_db, config=config)
    with TestClient(app, follow_redirects=False) as client:
        codes = [client.get("/auth/oauth2/github/login").status_code for _ in range(12)]
    assert codes == [307] * 10 + [429, 429]


def test_oauth2_callback_is_rate_limited(get_db, oauth2_test_config, monkeypatch):
    """Rejected states still spend the budget — floods can't probe for free."""
    stub_oauth2_provider(monkeypatch)
    config = oauth2_test_config.model_copy(update={"rate_limit": RateLimitConfig()})
    app, _ = build_oauth2_app(get_db, config=config)
    with TestClient(app, follow_redirects=False) as client:
        codes = [
            client.get("/auth/oauth2/github/callback?code=x&state=y").status_code
            for _ in range(6)
        ]
    assert codes == [400] * 5 + [429]
