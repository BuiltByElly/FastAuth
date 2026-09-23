"""Minimal FastAuth app: models + auth router mounting."""

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fastauth import (
    JWTAuth,
)
from fastauth.adapters import SQLAlchemyJWTAdapter
from fastauth.adapters.rate_limit import SQLAlchemyRateLimiter
from fastauth.config import CookieConfig, FastAuthConfig, JWTConfig, RateLimitConfig
from fastauth.dependencies.rate_limiter import RateLimiter
from fastauth.hooks.exceptions import HookAbort
from fastauth.hooks.login import LoginFailure
from fastauth.models import (
    FastAuthRateLimitMixin,
    FastAuthRefreshTokenMixin,
    FastAuthUserMixin,
)

from .database import engine, get_db


class Base(DeclarativeBase):
    """App declarative base for all models."""


class User(Base, FastAuthUserMixin):
    """App user table with FastAuth columns."""

    __tablename__ = "users"
    role: Mapped[str] = mapped_column(
        String(20), info={"fastauth_input": True, "fastauth_returned": True}
    )
    bio: Mapped[str | None] = mapped_column(
        String, info={"fastauth_input": True, "fastauth_returned": False}
    )
    notes: Mapped[str | None] = mapped_column(
        String, info={"fastauth_input": False, "fastauth_returned": False}
    )  # both default False — invisible in and out


class RefreshToken(Base, FastAuthRefreshTokenMixin):
    """App refresh token table linked to User."""

    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)


class RateLimitModel(Base, FastAuthRateLimitMixin):
    """App rate limit model."""

    __tablename__ = "rate_limits"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables on startup, dispose engine on shutdown."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(lifespan=lifespan)

rate_limiter = RateLimiter(
    rate_limit_model=RateLimitModel,
    rate_limiter_adapter=SQLAlchemyRateLimiter,
    db_session_dependency=get_db,
    rate_limit_config=RateLimitConfig(storage="database"),
)

auth = JWTAuth(
    adapter=SQLAlchemyJWTAdapter,
    user_model=User,
    refresh_model=RefreshToken,
    config=FastAuthConfig(
        jwt=JWTConfig(secret_key="gt0tl4mZRz/XQ7+i96tPYh1XHg8U7FiU62a9QJG3n6s="),
        cookies=CookieConfig(refresh_cookie_name="refreshing"),
    ),
    db_session_dependency=get_db,
    rate_limiter=rate_limiter,
)

app.include_router(auth.router)


@auth.on_before_signup
async def normalize_email(payload, request: Request):
    payload.email = payload.email.upper()
    print("payload on_before_signup", payload)
    return payload


@auth.on_before_login
async def blocking_ip(payload, request: Request):
    payload.email = payload.email.upper()
    if request.client is not None and request.client.host != "127.0.0.1":
        raise HookAbort(status_code=403, detail="Your IP is blocked skii")
    return payload


@auth.on_login_failure
async def _(failure: LoginFailure, request: Request):
    print("login failure", failure)


@auth.on_after_login
async def _(user, request: Request):
    print("user logged in", user)


@auth.on_after_logout
async def _(user_id: str):
    print("user logged out", user_id)


@auth.on_token_reuse_detected
async def _(user_id, request: Request):
    print("token reuse detected", user_id)
