"""Unit tests: static and dynamically-built request/response schemas."""

import pytest
from pydantic import ValidationError

from fastauth.config import PasswordConfig
from fastauth.schemas import (
    LoginRequest,
    SignupBase,
    build_login_schema,
    build_signup_schema,
    build_user_response_schema,
)


def test_default_password_policy_is_8_to_128():
    with pytest.raises(ValidationError):
        SignupBase(email="a@example.com", password="short")
    with pytest.raises(ValidationError):
        LoginRequest(email="a@example.com", password="x" * 129)
    assert (
        SignupBase(
            email="a@example.com", password="long-enough"
        ).password.get_secret_value()
        == "long-enough"
    )


def test_custom_password_policy_flows_through_builders():
    pc = PasswordConfig(min_length=12)
    signup = build_signup_schema({}, password_config=pc)
    login = build_login_schema(password_config=pc)
    with pytest.raises(ValidationError):
        signup(email="a@example.com", password="only-eight")
    with pytest.raises(ValidationError):
        login(email="a@example.com", password="only-eight")
    assert (
        login(
            email="a@example.com", password="twelve-chars!"
        ).password.get_secret_value()
        == "twelve-chars!"
    )


def test_login_builder_defaults_to_static_schema():
    assert build_login_schema() is LoginRequest


def test_signup_builder_merges_extra_fields():
    schema = build_signup_schema({"role": (str, ...)})
    user = schema(email="a@example.com", password="long-enough", role="admin")
    assert user.role == "admin"
    with pytest.raises(ValidationError):
        schema(email="a@example.com", password="long-enough")


def test_user_response_schema_merges_returned_fields():
    schema = build_user_response_schema({"role": (str, ...)})
    import uuid

    user = schema(id=uuid.uuid4(), email="a@example.com", is_active=True, role="admin")
    assert user.role == "admin"
    assert user.is_active is True


def test_user_response_rejects_bad_email():
    schema = build_user_response_schema({})
    import uuid

    with pytest.raises(ValidationError):
        schema(id=uuid.uuid4(), email="not-an-email", is_active=True)
