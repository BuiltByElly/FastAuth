"""Minimal FastAuth app: models + auth router mounting."""

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fastauth import SessionAuth
from fastauth.adapters import SQLAlchemySessionAdapter
from fastauth.config import (
    CookieConfig,
    FastAuthConfig,
    PasswordConfig,
)
from fastauth.hooks.exceptions import HookAbort
from fastauth.hooks.login import LoginFailure
from fastauth.models import FastAuthSessionMixin, FastAuthUserMixin

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


class Session(Base, FastAuthSessionMixin):
    """App session table linked to User."""

    __tablename__ = "sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables on startup, dispose engine on shutdown."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(lifespan=lifespan)

auth = SessionAuth(
    adapter=SQLAlchemySessionAdapter,
    user_model=User,
    session_model=Session,
    config=FastAuthConfig(
        cookies=CookieConfig(session_cookie_name="sessioning"),
        password=PasswordConfig(
            hash_schemes=["bcrypt"],
        ),
    ),
    db_session_dependency=get_db,
)

app.include_router(auth.router)
# auth.


@auth.on_before_signup
async def normalize_email(payload, request: Request):
    payload.email = payload.email.upper()
    print("payload on_before_signup", payload)
    return payload


@auth.on_signup_failure
async def _(err: str, request: Request):
    print("signup failure", err)


@auth.on_after_signup
async def _(user, request: Request):
    print("user signed up", user)


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
async def _(user):
    print("user logged out", user)
