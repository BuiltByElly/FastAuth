# Quickstart

Complete runnable app (SQLite): models with FastAuth mixins, per-request sessions, a `SessionAuth` instance, its router mounted, one protected route. Full version at `examples/basic/main.py` (hooks, password reset, Redis limiter); PostgreSQL variant: swap the driver URL and `get_db` stays the same shape.

```python
import uuid
from collections.abc import AsyncGenerator

from fastapi import Depends, FastAPI
from sqlalchemy import ForeignKey
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fastauth import SessionAuth
from fastauth.adapters.sqlalchemy import SQLAlchemySessionAdapter
from fastauth.adapters.sqlalchemy.models import (
    FastAuthSessionMixin,
    FastAuthUserMixin,
)


class Base(DeclarativeBase):
    """App declarative base for all models."""


class User(Base, FastAuthUserMixin):
    __tablename__ = "users"


class Session(Base, FastAuthSessionMixin):
    __tablename__ = "sessions"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))


engine = create_async_engine("sqlite+aiosqlite:///./test.db")
async_session_factory = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession]:
    """Yield one request-scoped session. Keep expire_on_commit=False."""
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


auth = SessionAuth(
    adapter=SQLAlchemySessionAdapter,
    user_model=User,
    session_model=Session,
    db_session_dependency=get_db,
)

app = FastAPI()
app.include_router(auth.router)


@app.get("/protected")
async def protected(user=Depends(auth.current_user)):
    return {"email": user.email}
```

This mounts, under `/auth`:

- `POST /auth/signup` → creates the user (extra columns tagged `fastauth_input` become signup fields)
- `POST /auth/login` → sets the session cookie
- `POST /auth/logout`, `GET /auth/me`
- `POST /auth/forgot-password`, `POST /auth/reset-password`

Extra model columns tagged `fastauth_returned` are included in responses and `fastauth_input` are included in requests; untagged columns stay invisible. See `examples/basic/main.py` for `role`/`bio`/`notes` doing exactly this.

Next: pick a [session](../strategies/session.md) or [JWT](../strategies/jwt.md) strategy, or add [OIDC](../strategies/oidc.md) / [OAuth2](../strategies/oauth2.md) login alongside. Full constructor signatures: [API reference](../reference/api.md#entry-points-fastauth-fastauthcore).
