# FastAuth

Simple and flexible authentication library for FastAPI — FastAPI-only by design.

Session, JWT, OIDC, and plain OAuth2 strategies. One class per strategy, one config object, your own SQLAlchemy or any ORM models. Asynchronous end to end.

## What it is

FastAuth is a FastAPI-native authentication library: secure defaults out of the box, pluggable underneath. One class per strategy, one `FastAuthConfig` for tuning, your own SQLAlchemy models for storage. Async-only core.

## Why it exists

Better Auth-style developer experience didn't exist for FastAPI specifically. FastAuth is FastAPI-only on purpose — not framework-agnostic — so it can lean on FastAPI dependencies, Pydantic validation, and `async` end to end instead of abstracting over them.

## Current state

Working now:

- **Session strategy** — cookie transport, server-side rows (`SessionAuth`)
- **JWT strategy** — short-lived bearer tokens + rotating refresh cookies (`JWTAuth`)
- **OIDC login** — Google-style providers with discovery doc + verified `id_token` (`OIDCAuth`)
- **Plain OAuth2 login** — GitHub-style providers with no discovery doc (`OAuth2Auth`)
- **Rate limiting** — in-memory (default), database, or Redis backends
- **Event hooks** — before/observer hooks on signup, login, logout, refresh, password reset, and OAuth logins
- **Config validation** — bad values fail at startup, not in production

## Installation

Requires Python 3.14+ and [`uv`](https://docs.astral.sh/uv/).

```bash
uv add builtbyelly-fastauth
```

SQLAlchemy and the redis client ship in the default install — no extras. Optional dependencies for other ORMs will arrive over time as more backends land. Add an async DB driver for your database:

```bash
uv add aiosqlite   # SQLite, as used in examples/
```

## Quickstart

Define models with the mixins, build the auth instance, mount the router, protect routes with `auth.current_user` (from `examples/basic/main.py`):

```python
from fastapi import Depends, FastAPI
from sqlalchemy import ForeignKey
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fastauth import SessionAuth
from fastauth.adapters.sqlalchemy import SQLAlchemySessionAdapter
from fastauth.adapters.sqlalchemy.models import (
    FastAuthSessionMixin,
    FastAuthUserMixin,
)


class Base(DeclarativeBase): ...


class User(Base, FastAuthUserMixin):
    __tablename__ = "users"


class Session(Base, FastAuthSessionMixin):
    __tablename__ = "sessions"
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"))


auth = SessionAuth(
    adapter=SQLAlchemySessionAdapter,
    user_model=User,
    session_model=Session,
    db_session_dependency=get_db,  # your FastAPI dep yielding an AsyncSession
)

app = FastAPI()
app.include_router(auth.router)


@app.get("/protected")
async def protected(user=Depends(auth.current_user)):
    return {"email": user.email}
```

That mounts `POST /auth/signup`, `POST /auth/login`, `POST /auth/logout`, `POST /auth/forgot-password`, `POST /auth/reset-password`, and `GET /auth/me`. See `examples/` for full apps: `basic` (sessions), `jwt_example` (JWT + DB rate limiting), `oidc` (Google), `oauth2` (GitHub).

## Features

- **Sessions** — `HttpOnly`/`Secure`/`SameSite` cookies, server-side expiry, rotation on login
- **JWT** — 10-minute access tokens, single-use rotating refresh tokens, reuse detection
- **OIDC** — per-provider config, `state` CSRF protection, signature + `iss`/`aud`/`exp` verification
- **Plain OAuth2** — explicit URLs, dev-supplied `map_profile_to_user`, provider tokens handed to your hook, never persisted
- **Adapters** — SQLAlchemy included; bring your own ORM by subclassing `Adapter`
- **Hooks** — `on_before_signup`, `on_after_login`, `on_after_oidc_login`, `on_after_oauth2_login`, and more; before-hooks can mutate or `HookAbort`, observers never break the response
- **Rate limiting** — fixed-window, per-IP + path; memory, database (row-locked), or Redis (Lua-atomic) storage
- **Config** — one frozen `FastAuthConfig`; placeholder secrets rejected, lifetimes bounded

## Docs

Full docs live in `docs/` (zensical): `uvx zensical serve`. Start at `docs/getting-started/quickstart.md`. `ARCHITECTURE.md` covers the internals. Agents: see `llms.txt` (library use) and `AGENTS.md` (contributing).
Link to docs: [https://builtbyelly.github.io/FastAuth/](https://builtbyelly.github.io/FastAuth/)

## License

MIT.
