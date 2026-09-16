"""Request/response schemas. Dynamic ones merge dev extras at startup."""

import uuid
from typing import Any

from pydantic import BaseModel, create_model


class SignupBase(BaseModel):
    """Core fields every signup requires, regardless of dev extras."""

    email: str
    password: str


class LoginRequest(BaseModel):
    """Static: login never takes extra fields."""

    email: str
    password: str


class UserResponseBase(BaseModel):
    """Core fields every user response returns, regardless of dev extras."""

    id: uuid.UUID
    email: str
    is_active: bool


class TokenResponse(BaseModel):
    """JWT login/refresh response (placeholder scheme until real signing)."""

    access_token: str
    token_type: str = "bearer"


class SessionResponse(BaseModel):
    """Session login response: token id plus expiry."""

    session_id: str
    expires_at: str


def build_signup_schema(extra_fields: dict[str, Any]) -> type[BaseModel]:
    """Combine SignupBase with dev columns tagged fastauth_input=True."""
    return create_model("SignupRequest", __base__=SignupBase, **extra_fields)  # type: ignore[call-overload]


def build_user_response_schema(extra_fields: dict[str, Any]) -> type[BaseModel]:
    """Combine UserResponseBase with dev columns tagged fastauth_returned=True."""
    return create_model("UserResponse", __base__=UserResponseBase, **extra_fields)  # type: ignore[call-overload]
