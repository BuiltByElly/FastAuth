"""Security: forged, tampered, expired, and confused JWTs must all fail closed."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt as pyjwt
import pytest
from sqlalchemy import select

from tests.conftest import TEST_SECRET, User, cookie_value


def _bearer(client, token):
    return client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})


def _mint(payload, secret=TEST_SECRET, algorithm="HS256"):
    return pyjwt.encode(payload, secret, algorithm=algorithm)


def _access_payload(user_id, **overrides):
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "exp": now + timedelta(minutes=10),
        "iat": now,
        "jti": uuid.uuid4().hex,
        "type": "access",
    }
    payload.update(overrides)
    return payload


@pytest.fixture
async def user_id(jwt_client, session_factory):
    """A real user id, fetched straight from the database."""
    jwt_client.post(
        "/auth/signup", json={"email": "u@example.com", "password": "long-enough"}
    )
    async with session_factory() as session:
        return (await session.execute(select(User))).scalar_one().id


def test_forged_signature_rejected(jwt_client, user_id):
    header, payload, _ = _mint(_access_payload(user_id)).split(".")
    forged = f"{header}.{payload}.{'A' * 43}"
    assert _bearer(jwt_client, forged).status_code == 401


def test_wrong_secret_rejected(jwt_client, user_id):
    token = _mint(_access_payload(user_id), secret="0" * 40)
    assert _bearer(jwt_client, token).status_code == 401


def test_none_algorithm_rejected(jwt_client, user_id):
    token = _mint({**_access_payload(user_id)}, secret="", algorithm="none")
    assert _bearer(jwt_client, token).status_code == 401


def test_wrong_algorithm_rejected(jwt_client, user_id):
    token = _mint(_access_payload(user_id), algorithm="HS384")
    assert _bearer(jwt_client, token).status_code == 401


def test_expired_token_rejected(jwt_client, user_id):
    now = datetime.now(UTC)
    token = _mint({
        "sub": str(user_id),
        "exp": now - timedelta(seconds=1),
        "iat": now - timedelta(minutes=11),
        "jti": uuid.uuid4().hex,
        "type": "access",
    })
    assert _bearer(jwt_client, token).status_code == 401


def test_tampered_payload_rejected(jwt_client, user_id):
    header, payload, sig = _mint(_access_payload(user_id)).split(".")
    tampered = ("B" if payload[0] != "B" else "C") + payload[1:]
    assert _bearer(jwt_client, f"{header}.{tampered}.{sig}").status_code == 401


def test_tampered_header_rejected(jwt_client, user_id):
    header, payload, sig = _mint(_access_payload(user_id)).split(".")
    tampered = ("B" if header[0] != "B" else "C") + header[1:]
    assert _bearer(jwt_client, f"{tampered}.{payload}.{sig}").status_code == 401


@pytest.mark.parametrize("drop", ["sub", "exp"])
def test_missing_required_claim_rejected(jwt_client, user_id, drop):
    payload = _access_payload(user_id)
    del payload[drop]
    assert _bearer(jwt_client, _mint(payload)).status_code == 401


def test_refresh_token_rejected_as_access(jwt_client, user_id):
    token = _mint(_access_payload(user_id, type="refresh"))
    assert _bearer(jwt_client, token).status_code == 401


def test_unknown_user_rejected(jwt_client):
    token = _mint(_access_payload(uuid.uuid4()))
    assert _bearer(jwt_client, token).status_code == 401


def test_non_uuid_subject_rejected(jwt_client):
    token = _mint(_access_payload("admin"))
    assert _bearer(jwt_client, token).status_code == 401


def test_placeholder_scheme_is_dead(jwt_client, user_id):
    assert _bearer(jwt_client, f"fastauth.{user_id}.anything").status_code == 401


@pytest.mark.parametrize("token", ["", "garbage", "a.b", "a.b.c.d", ".".join(["x" * 100] * 3)])
def test_malformed_tokens_rejected(jwt_client, token):
    assert _bearer(jwt_client, token).status_code == 401
