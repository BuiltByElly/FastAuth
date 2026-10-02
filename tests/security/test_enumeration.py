"""Security: login must not reveal whether an email is registered."""

import pytest
from fastapi.testclient import TestClient

from tests.conftest import build_session_app


def _login(client, email, password="long-enough"):
    return client.post("/auth/login", json={"email": email, "password": password})


@pytest.mark.parametrize(
    "email,password",
    [
        ("nobody@example.com", "long-enough"),  # unknown email, valid-shaped password
        ("u@example.com", "wrong-pass-1"),  # known email, wrong password
        ("nobody@example.com", "wrong-pass-1"),  # unknown email, wrong password
    ],
)
def test_login_failures_are_indistinguishable(seeded_client, email, password):
    """Same status, same message — no oracle for account enumeration."""
    response = _login(seeded_client, email, password)
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid credentials."}


@pytest.fixture
def seeded_client(get_db, test_config):
    """Client with one registered user (rate limiting disabled)."""
    app, _ = build_session_app(get_db, config=test_config)
    with TestClient(app) as client:
        client.post(
            "/auth/signup", json={"email": "u@example.com", "password": "long-enough"}
        )
        yield client


def test_signup_duplicate_deliberately_discloses(seeded_client):
    """Signup MUST say an email is taken (else users can't recover typos);
    document the accepted enumeration trade-off instead of hiding it."""
    response = seeded_client.post(
        "/auth/signup", json={"email": "u@example.com", "password": "long-enough"}
    )
    assert response.status_code == 400
    assert response.json() == {"detail": "Email already registered"}


def test_forgot_password_never_reveals_registration(seeded_client):
    """Known vs unknown email: byte-identical status + body."""
    known = seeded_client.post(
        "/auth/forgot-password", json={"email": "u@example.com"}
    )
    unknown = seeded_client.post(
        "/auth/forgot-password", json={"email": "ghost@example.com"}
    )
    assert known.status_code == unknown.status_code == 200
    assert known.json() == unknown.json() == {
        "detail": "If that email exists, a reset link was sent."
    }


def test_reset_password_rejects_garbage_without_oracle(seeded_client):
    """Unknown, empty-ish, and malformed tokens share one 400 body."""
    for token in ("never-issued", "x", "a.b.c"):
        response = seeded_client.post(
            "/auth/reset-password",
            json={"token": token, "new_password": "brand-new-password"},
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "Invalid or expired token."}
