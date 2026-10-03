"""Minimal FastAuth app: models + auth router mounting."""

import uuid
from contextlib import asynccontextmanager
from typing import Annotated

import httpx2
from fastapi import Depends, FastAPI, Request
from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from starlette.config import Config

from fastauth.adapters.sqlalchemy import SQLAlchemySessionAdapter
from fastauth.adapters.sqlalchemy.models import (
    FastAuthOAuthAccountMixin,
    FastAuthSessionMixin,
    FastAuthUserMixin,
)
from fastauth.config import (
    FastAuthConfig,
    OAuth2Config,
    OAuth2ProviderConfig,
)
from fastauth.core import OAuth2Auth
from fastauth.types import OAuthUserInfo

from .database import engine, get_db


class Base(DeclarativeBase):
    """App declarative base for all models."""


class User(Base, FastAuthUserMixin):
    """App user table with FastAuth columns."""

    __tablename__ = "users"
    role: Mapped[str] = mapped_column(
        String(20),
        info={"fastauth_input": True, "fastauth_returned": True},
        nullable=True,
    )
    bio: Mapped[str | None] = mapped_column(
        String, info={"fastauth_input": True, "fastauth_returned": False}, nullable=True
    )
    notes: Mapped[str | None] = mapped_column(
        String,
        info={"fastauth_input": False, "fastauth_returned": False},
        nullable=True,
    )  # both default False — invisible in and out


class Session(Base, FastAuthSessionMixin):
    """App session table linked to User."""

    __tablename__ = "sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))


class OAuth2Account(Base, FastAuthOAuthAccountMixin):
    __tablename__ = "oauth2_accounts"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)

    __table_args__ = (
        UniqueConstraint(
            "provider", "provider_user_id", name="uq_oauth_provider_account"
        ),  # mandatory
        UniqueConstraint(
            "provider", "user_id", name="uq_oauth_provider_per_user"
        ),  # optional
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Create tables on startup, dispose engine on shutdown."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(lifespan=lifespan)


config = Config(".env")


async def map_github_profile(profile: dict) -> OAuthUserInfo:
    email = profile.get("email")

    known_keys = {"id", "email", "email_verified", "name", "avatar_url"}
    others = {k: v for k, v in profile.items() if k not in known_keys}

    return OAuthUserInfo(
        provider="github",
        provider_user_id=str(profile["id"]),
        email=email,
        email_verified=True,  # GitHub only returns verified emails via this endpoint
        name=profile.get("name") or profile.get("login"),
        avatar_url=profile.get("avatar_url"),
        others=others or None,
    )


GITHUB_CONFIG = OAuth2ProviderConfig(
    name="github",
    client_id=config("GITHUB_CLIENT_ID"),
    client_secret=config("GITHUB_CLIENT_SECRET"),
    redirect_uri="http://localhost:8000/auth/oauth2/github/callback",
    authorization_url="https://github.com/login/oauth/authorize",
    token_url="https://github.com/login/oauth/access_token",
    userinfo_url="https://api.github.com/user",
    scopes=["read:user", "user:email"],
    map_profile_to_user=map_github_profile,
)


oauth2 = OAuth2Auth(
    adapter=SQLAlchemySessionAdapter,
    user_model=User,
    session_model=Session,
    config=FastAuthConfig(
        oauth2=OAuth2Config(secret_key=config("SECRET_KEY"), providers=[GITHUB_CONFIG])
    ),
    db_session_dependency=get_db,
    strategy="session",
    oauth_account_model=OAuth2Account,
)

app.include_router(oauth2.router)


@app.get("/")
async def root(current_user: Annotated[User | None, Depends(oauth2.current_user)]):
    return {"message": "Hello World"}


@oauth2.on_after_oauth2_login
async def _(user, request: Request):
    print("user", user)
