"""Integration: full OAuth2 lifecycle over HTTP (provider stubbed, no network)."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from fastauth.types import OAuth2LoginResult
from tests.conftest import (
    OAuth2Account,
    User,
    build_oauth2_app,
    oauth2_begin,
    stub_oauth2_provider,
)


@pytest.fixture
def app_pair(get_db, oauth2_test_config, monkeypatch):
    """Session-strategy OAuth2 app + auth instance (rate limiting disabled)."""
    stub_oauth2_provider(monkeypatch)
    return build_oauth2_app(get_db, config=oauth2_test_config)


@pytest.fixture
def client(app_pair):
    app, _ = app_pair
    with TestClient(app, follow_redirects=False) as test_client:
        yield test_client


def _callback(client, state, provider="github"):
    return client.get(f"/auth/oauth2/{provider}/callback?code=code&state={state}")


async def test_session_signin_creates_user_account_and_session(client, session_factory):
    response = _callback(client, oauth2_begin(client))
    assert response.status_code == 200
    assert response.json() == {"success": True, "message": "Logged in successfully"}
    assert client.cookies.get("fastauth_session")
    assert client.get("/protected").json() == {"email": "u@example.com"}

    async with session_factory() as session:
        users = (await session.execute(select(User))).scalars().all()
        assert len(users) == 1
        assert users[0].hashed_password is None  # OAuth2 users have no password
        accounts = (await session.execute(select(OAuth2Account))).scalars().all()
        assert [(a.provider, a.provider_user_id) for a in accounts] == [
            ("github", "gh-1")
        ]


async def test_second_signin_links_to_same_account(client, session_factory):
    assert _callback(client, oauth2_begin(client)).status_code == 200
    first_session = client.cookies.get("fastauth_session")

    client.cookies.clear()
    assert _callback(client, oauth2_begin(client)).status_code == 200
    second_session = client.cookies.get("fastauth_session")
    assert second_session and second_session != first_session
    assert client.get("/protected").status_code == 200

    async with session_factory() as session:
        # Linked by (provider, sub) — no duplicate identity rows.
        assert len((await session.execute(select(User))).scalars().all()) == 1
        assert len((await session.execute(select(OAuth2Account))).scalars().all()) == 1


async def test_jwt_strategy_issues_working_credentials(
    get_db, oauth2_test_config, jwt_config, monkeypatch, session_factory
):
    stub_oauth2_provider(monkeypatch)
    config = oauth2_test_config.model_copy(update={"jwt": jwt_config})
    app, _ = build_oauth2_app(get_db, config=config, strategy="jwt")
    with TestClient(app, follow_redirects=False) as client:
        response = _callback(client, oauth2_begin(client))
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
            accounts = (await session.execute(select(OAuth2Account))).scalars().all()
            assert len(accounts) == 1


def test_after_login_hook_receives_oauth2_result(
    get_db, oauth2_test_config, monkeypatch
):
    stub_oauth2_provider(monkeypatch)
    app, auth = build_oauth2_app(get_db, config=oauth2_test_config)
    received = []

    @auth.on_after_oauth2_login
    async def capture(result, request):
        received.append(result)

    with TestClient(app, follow_redirects=False) as client:
        assert _callback(client, oauth2_begin(client)).status_code == 200

    assert len(received) == 1
    result = received[0]
    # Unlike OIDC (user info only), OAuth2 hands over the provider tokens too —
    # FastAuth never persists them, the dev decides what to do.
    assert isinstance(result, OAuth2LoginResult)
    assert result.user_info.provider == "github"
    assert result.user_info.provider_user_id == "gh-1"
    assert result.access_token == "provider-at"
