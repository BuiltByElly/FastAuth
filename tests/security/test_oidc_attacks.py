"""Security: OIDC state/CSRF hardening, deactivated accounts, IdP-claim abuse.

The IdP is stubbed (`stub_oidc_provider`) — every test exercises FastAuth's
own verification, never the network.
"""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from fastauth.config import (
    CookieConfig,
    FastAuthConfig,
    OIDCConfig,
    OIDCProviderConfig,
    RateLimitConfig,
)
from fastauth.oauth.oidc import OIDCStateManager
from fastauth.security import verify_password
from tests.conftest import (
    OIDCAccount,
    User,
    build_oidc_app,
    create_user,
    oidc_begin,
    stub_oidc_provider,
)

STATE_COOKIE = "fastauth_oidc_state"
STATE_REJECTED = {"detail": "Invalid or expired state"}


def _google(**overrides):
    values = {
        "name": "google",
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "redirect_uri": "http://testserver/auth/oidc/google/callback",
        "metadata_url": "https://idp.example/.well-known/openid-configuration",
    }
    values.update(overrides)
    return OIDCProviderConfig(**values)


def _callback(client, state, provider="google"):
    return client.get(f"/auth/oidc/{provider}/callback?code=code&state={state}")


def _assert_rejected(response):
    """Same status, same body — no oracle for what went wrong."""
    assert response.status_code == 400
    assert response.json() == STATE_REJECTED


@pytest.fixture
def oidc_app(get_db, oidc_test_config, monkeypatch):
    """Session-strategy OIDC app with a stubbed IdP (rate limiting off)."""
    stub_oidc_provider(monkeypatch)
    return build_oidc_app(get_db, config=oidc_test_config)


@pytest.fixture
def client(oidc_app):
    app, _ = oidc_app
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


# --- login: redirect + state cookie hardening --------------------------------


def test_login_redirects_to_provider_with_fresh_state(client):
    response = client.get("/auth/oidc/google/login")
    assert response.status_code == 307
    location = response.headers["location"]
    assert location.startswith("https://idp.example/authorize?")
    assert "state=" in location
    assert client.cookies.get(STATE_COOKIE)  # round-trips via cookie on callback


def test_state_cookie_flags_are_hardened(get_db, oidc_config, monkeypatch):
    """Default (production) cookie flags, read off the raw header."""
    stub_oidc_provider(monkeypatch)
    config = FastAuthConfig(
        cookies=CookieConfig(secure=True),
        rate_limit=RateLimitConfig(enabled=False),
        oidc=oidc_config,
    )
    app, _ = build_oidc_app(get_db, config=config)
    with TestClient(app, follow_redirects=False) as client:
        response = client.get("/auth/oidc/google/login")
    header = response.headers["set-cookie"]
    assert header.startswith(f"{STATE_COOKIE}=")
    assert "HttpOnly" in header  # no JS access → XSS can't steal it
    assert "Secure" in header  # HTTPS only
    assert "SameSite=lax" in header  # no cross-site sends
    assert "Max-Age=300" in header  # short-lived CSRF window
    assert "Path=/" in header


def test_state_cookie_is_cleared_after_callback(client):
    state = oidc_begin(client)
    assert _callback(client, state).status_code == 200
    assert client.cookies.get(STATE_COOKIE) is None


# --- callback: state verification --------------------------------------------


def test_callback_without_state_cookie_is_rejected(client):
    state = oidc_begin(client)
    client.cookies.clear()
    _assert_rejected(_callback(client, state))


def test_callback_with_mismatched_state_is_rejected(client):
    state = oidc_begin(client)
    assert state != "A" * 43
    _assert_rejected(_callback(client, "A" * 43))


def test_callback_with_forged_state_cookie_is_rejected(client):
    state = oidc_begin(client)
    client.cookies.set(STATE_COOKIE, "forged.deadbeef")
    _assert_rejected(_callback(client, state))


def test_state_cannot_be_replayed(client):
    state = oidc_begin(client)
    assert _callback(client, state).status_code == 200
    # First callback consumed the cookie — replay has nothing to verify.
    _assert_rejected(_callback(client, state))


def test_expired_state_is_rejected(get_db, oidc_test_config, monkeypatch):
    stub_oidc_provider(monkeypatch)
    app, auth = build_oidc_app(get_db, config=oidc_test_config)
    # Same signing secret, zero tolerance for age.
    auth.ctx.state_manager = OIDCStateManager(secret_key="o" * 40, max_age=-1)
    with TestClient(app, follow_redirects=False) as client:
        state = oidc_begin(client)
        _assert_rejected(_callback(client, state))


def test_state_is_bound_to_its_provider(get_db, oidc_test_config, monkeypatch):
    """A state minted for google must not authorize a microsoft callback."""
    stub_oidc_provider(monkeypatch)
    config = oidc_test_config.model_copy(
        update={
            "oidc": OIDCConfig(
                secret_key="o" * 40,
                providers=[
                    _google(),
                    _google(
                        name="microsoft",
                        client_id="other-id",
                        client_secret="other-secret",
                        redirect_uri="http://testserver/auth/oidc/microsoft/callback",
                    ),
                ],
            )
        }
    )
    app, _ = build_oidc_app(get_db, config=config)
    with TestClient(app, follow_redirects=False) as client:
        google_state = oidc_begin(client, "google")
        _assert_rejected(_callback(client, google_state, "microsoft"))


def test_unknown_provider_is_404(client):
    assert client.get("/auth/oidc/nope/login").status_code == 404
    assert (
        client.get("/auth/oidc/nope/callback?code=x&state=y").status_code == 404
    )


# --- account abuse ------------------------------------------------------------


async def test_deactivated_account_cannot_sign_in_again(
    get_db, oidc_test_config, monkeypatch, session_factory
):
    stub_oidc_provider(monkeypatch)
    app, _ = build_oidc_app(get_db, config=oidc_test_config)
    with TestClient(app, follow_redirects=False) as client:
        assert _callback(client, oidc_begin(client)).status_code == 200
        assert client.get("/protected").status_code == 200

        async with session_factory() as session:
            user = (await session.execute(select(User))).scalar_one()
            user.is_active = False
            await session.commit()

        client.cookies.clear()
        response = _callback(client, oidc_begin(client))
        assert response.status_code == 403
        assert response.json() == {"detail": "Account is inactive."}
        assert client.cookies.get("fastauth_session") is None
        assert client.get("/protected").status_code == 401


async def test_idp_email_claim_cannot_take_over_password_account(
    get_db, oidc_test_config, monkeypatch, session_factory
):
    await create_user(session_factory, email="u@example.com", password="long-enough")
    stub_oidc_provider(monkeypatch, email="u@example.com")
    app, _ = build_oidc_app(get_db, config=oidc_test_config)
    with TestClient(app, follow_redirects=False) as client:
        response = _callback(client, oidc_begin(client))
        assert response.status_code == 400
        assert response.json() == {"detail": "Email already registered"}
        assert client.cookies.get("fastauth_session") is None
        assert client.get("/protected").status_code == 401

    async with session_factory() as session:
        users = (await session.execute(select(User))).scalars().all()
        # Exactly the seeded account, still password-only, untouched.
        assert len(users) == 1
        assert verify_password("long-enough", users[0].hashed_password)
        assert (await session.execute(select(OIDCAccount))).scalars().all() == []


async def test_orphaned_account_row_fails_closed(
    get_db, oidc_test_config, monkeypatch, session_factory
):
    """Account row whose user was deleted: no crash, no resurrection."""
    stub_oidc_provider(monkeypatch)
    app, _ = build_oidc_app(get_db, config=oidc_test_config)
    with TestClient(app, follow_redirects=False) as client:
        assert _callback(client, oidc_begin(client)).status_code == 200
        async with session_factory() as session:
            await session.execute(delete(User))
            await session.commit()

        client.cookies.clear()
        response = _callback(client, oidc_begin(client))
        assert response.status_code == 401
        assert client.cookies.get("fastauth_session") is None

        async with session_factory() as session:
            assert (await session.execute(select(User))).scalars().all() == []
            accounts = (await session.execute(select(OIDCAccount))).scalars().all()
            assert len(accounts) == 1  # row remains, but grants nothing


# --- rate limiting ------------------------------------------------------------


def test_oidc_login_is_rate_limited(get_db, oidc_test_config, monkeypatch):
    stub_oidc_provider(monkeypatch)
    config = oidc_test_config.model_copy(update={"rate_limit": RateLimitConfig()})
    app, _ = build_oidc_app(get_db, config=config)
    with TestClient(app, follow_redirects=False) as client:
        codes = [client.get("/auth/oidc/google/login").status_code for _ in range(12)]
    assert codes == [307] * 10 + [429, 429]


def test_oidc_callback_is_rate_limited(get_db, oidc_test_config, monkeypatch):
    """Rejected states still spend the budget — floods can't probe for free."""
    stub_oidc_provider(monkeypatch)
    config = oidc_test_config.model_copy(update={"rate_limit": RateLimitConfig()})
    app, _ = build_oidc_app(get_db, config=config)
    with TestClient(app, follow_redirects=False) as client:
        codes = [
            client.get("/auth/oidc/google/callback?code=x&state=y").status_code
            for _ in range(6)
        ]
    assert codes == [400] * 5 + [429]
