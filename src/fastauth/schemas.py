"""Request/response schemas. Dynamic ones merge dev extras at startup."""

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, create_model

from fastauth.config import PasswordConfig


class SignupBase(BaseModel):
    """Core fields every signup requires, regardless of dev extras."""

    email: EmailStr
    password: SecretStr = Field(min_length=8, max_length=128)


class LoginRequest(BaseModel):
    """Static: login never takes extra fields."""

    email: EmailStr
    password: SecretStr = Field(min_length=8, max_length=128)


class UserResponseBase(BaseModel):
    """Core fields every user response returns, regardless of dev extras."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    is_active: bool


class TokenResponse(BaseModel):
    """JWT login/refresh response: signed access token."""

    access_token: str
    token_type: str = "access"


class SessionResponse(BaseModel):
    """Session login response: token id plus expiry."""

    session_id: str
    expires_at: str


def _password_field(password_config: PasswordConfig | None = None) -> Any:
    """Password field honoring the configured policy (defaults 8..128)."""
    pc = password_config or PasswordConfig()
    return Field(min_length=pc.min_length, max_length=pc.max_length)


def build_signup_schema(
    extra_fields: dict[str, Any],
    password_config: PasswordConfig | None = None,
) -> type[BaseModel]:
    """Combine SignupBase with dev columns tagged fastauth_input=True."""
    if password_config is None:
        return create_model("SignupRequest", __base__=SignupBase, **extra_fields)  # type: ignore[call-overload]
    dyn_base = create_model(
        "SignupBase",
        __base__=BaseModel,
        email=(EmailStr, ...),
        password=(SecretStr, _password_field(password_config)),
    )
    return create_model("SignupRequest", __base__=dyn_base, **extra_fields)  # type: ignore[call-overload]


def build_login_schema(
    password_config: PasswordConfig | None = None,
) -> type[BaseModel]:
    """Login schema honoring the configured password policy."""
    if password_config is None:
        return LoginRequest
    return create_model(
        "LoginRequest",
        __base__=BaseModel,
        email=(EmailStr, ...),
        password=(SecretStr, _password_field(password_config)),
    )


def build_user_response_schema(extra_fields: dict[str, Any]) -> type[BaseModel]:
    """Combine UserResponseBase with dev columns tagged fastauth_returned=True."""
    return create_model("UserResponse", __base__=UserResponseBase, **extra_fields)  # type: ignore[call-overload]
