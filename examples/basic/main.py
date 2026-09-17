"""Minimal FastAuth app: models + auth router mounting."""

import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import ForeignKey, String
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fastauth import (
    CookieConfig,
    FastAuth,
    FastAuthConfig,
    PasswordConfig,
    SQLAlchemySessionAdapter,
)
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

auth = FastAuth(
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
    strategy="session",
)

app.include_router(auth.router)
