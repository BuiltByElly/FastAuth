"""Minimal FastAuth app: models + auth router mounting."""

import uuid
from contextlib import asynccontextmanager
from typing import Annotated

from authlib.integrations.starlette_client import OAuth
from fastapi import Depends, FastAPI, Request
from sqlalchemy import ForeignKey, String, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware

from fastauth import SessionAuth
from fastauth.adapters.sqlalchemy import SQLAlchemySessionAdapter
from fastauth.adapters.sqlalchemy.models import (
    FastAuthOIDCAccountMixin,
    FastAuthSessionMixin,
    FastAuthUserMixin,
)
from fastauth.config import FastAuthConfig, OIDCConfig, OIDCProviderConfig
from fastauth.core import OIDCAuth
from fastauth.routes import oidc_route

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


class OIDCAccount(Base, FastAuthOIDCAccountMixin):
    __tablename__ = "oidc_accounts"

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


oidc_providers = OIDCProviderConfig(
    name="google",
    client_id=config("GOOGLE_CLIENT_ID"),
    client_secret=config("GOOGLE_CLIENT_SECRET"),
    redirect_uri="http://localhost:8000/auth/oidc/google/callback",
    metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    scopes=["openid", "email", "profile"],
)
oidc = OIDCAuth(
    adapter=SQLAlchemySessionAdapter,
    user_model=User,
    session_model=Session,
    config=FastAuthConfig(
        oidc=OIDCConfig(secret_key=config("SECRET_KEY"), providers=[oidc_providers])
    ),
    db_session_dependency=get_db,
    oidc_account_model=OIDCAccount,
    strategy="session",
)

app.include_router(oidc.router)


@app.get("/")
async def root(current_user: Annotated[User | None, Depends(oidc.current_user)]):
    return {"message": "Hello World"}


@oidc.on_after_login
async def _(user, request: Request):
    print("user", user)
