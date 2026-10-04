"""Integration: full OIDC lifecycle over HTTP (IdP stubbed, no network)."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from fastauth.types import OAuthUserInfo
from tests.conftest import (
    OIDCAccount,
    User,
    build_oidc_app,
    oidc_begin,
    stub_oidc_provider,
)


@pytest.fixture
def app_pair(get_db, oidc_test_config, monkeypatch):
    """Session-strategy OIDC app + auth instance (rate limiting disabled)."""
    stub_oidc_provider(monkeypatch)
    return build_oidc_app(get_db, config=oidc_test_config)


@pytest.fixture
def client(app_pair):
    app, _ = app_pair
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


def _callback(client, state, provider="google"):
    return client.get(f"/auth/oidc/{provider}/callback?code=code&state={state}")


async def test_session_signin_creates_user_account_and_session(client, session_factory):
    response = _callback(client, oidc_begin(client))
    assert response.status_code == 200
    assert response.json() == {"success": True, "message": "Logged in successfully"}
    assert client.cookies.get("fastauth_session")
    assert client.get("/protected").json() == {"email": "u@example.com"}

    async with session_factory() as session:
        users = (await session.execute(select(User))).scalars().all()
        assert len(users) == 1
        assert users[0].hashed_password is None  # OIDC users have no password
        accounts = (await session.execute(select(OIDCAccount))).scalars().all()
        assert [(a.provider, a.provider_user_id) for a in accounts] == [
            ("google", "sub-1")
        ]


async def test_second_signin_links_to_same_account(client, session_factory):
    assert _callback(client, oidc_begin(client)).status_code == 200
    first_session = client.cookies.get("fastauth_session")

    client.cookies.clear()
    assert _callback(client, oidc_begin(client)).status_code == 200
    second_session = client.cookies.get("fastauth_session")
    assert second_session and second_session != first_session
    assert client.get("/protected").status_code == 200

    async with session_factory() as session:
        # Linked by (provider, sub) — no duplicate identity rows.
        assert len((await session.execute(select(User))).scalars().all()) == 1
        assert len((await session.execute(select(OIDCAccount))).scalars().all()) == 1


async def test_jwt_strategy_issues_working_credentials(
    get_db, oidc_test_config, jwt_config, monkeypatch, session_factory
):
    stub_oidc_provider(monkeypatch)
    config = oidc_test_config.model_copy(update={"jwt": jwt_config})
    app, _ = build_oidc_app(get_db, config=config, strategy="jwt")
    with TestClient(app, follow_redirects=False) as client:
        response = _callback(client, oidc_begin(client))
        assert response.status_code == 200
        access_token = response.json()["access_token"]
        assert len(access_token.split(".")) == 3  # real JWT shape
        assert client.cookies.get("fastauth_refresh")
        assert (
            client.get(
                "/protected", headers={"Authorization": f"Bearer {access_token}"}
            ).status_code
            == 200
        )

        # The account must outlive the request that created it.
        async with session_factory() as session:
            assert len((await session.execute(select(User))).scalars().all()) == 1
            accounts = (await session.execute(select(OIDCAccount))).scalars().all()
            assert len(accounts) == 1


def test_after_login_hook_receives_oidc_user_info(
    get_db, oidc_test_config, monkeypatch
):
    stub_oidc_provider(monkeypatch)
    app, auth = build_oidc_app(get_db, config=oidc_test_config)
    received = []

    @auth.on_after_oidc_login
    async def capture(user, request):
        received.append(user)

    with TestClient(app, follow_redirects=False) as client:
        assert _callback(client, oidc_begin(client)).status_code == 200

    assert len(received) == 1
    info = received[0]
    assert isinstance(info, OAuthUserInfo)
    assert info.provider == "google"
    assert info.provider_user_id == "sub-1"
    assert info.email == "u@example.com"
