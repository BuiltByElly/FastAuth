"""Dev-facing `current_user` dependencies, one per strategy.

Build them from an `AuthContext` (normally via `auth.current_user`, which
picks the right one for the instance's strategy), or call the builders
directly. Use as `Depends(auth.current_user)` in your own routes.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.cookies import REFRESH_COOKIE_NAME, SESSION_COOKIE_NAME
from fastauth.models import FastAuthUserMixin
from fastauth.routes.context import AuthContext

# Shared bearer scheme (auto_error=False so we raise 401, not 403).
security = HTTPBearer(auto_error=False)


def session_current_user(
    ctx: AuthContext,
) -> Callable[..., Awaitable[FastAuthUserMixin]]:
    """Build a dependency resolving the user from the session cookie."""

    async def _dependency(
        request: Request,
        session: Annotated[AsyncSession, Depends(ctx.db_session_dependency)],
    ) -> FastAuthUserMixin:
        token = request.cookies.get(SESSION_COOKIE_NAME)
        if token is None:
            raise HTTPException(status_code=401, detail="Missing session cookie.")
        user = await ctx.build_adapter(session).resolve_credential(token)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid or expired session.")
        return user

    return _dependency


def jwt_current_user(ctx: AuthContext) -> Callable[..., Awaitable[FastAuthUserMixin]]:
    """Build a dependency resolving the user from the bearer access token."""

    async def _dependency(
        session: Annotated[AsyncSession, Depends(ctx.db_session_dependency)],
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    ) -> FastAuthUserMixin:
        if credentials is None:
            raise HTTPException(
                status_code=401,
                detail="Missing bearer token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user = await ctx.build_adapter(session).resolve_credential(
            credentials.credentials
        )
        if user is None:
            raise HTTPException(
                status_code=401,
                detail="Invalid token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return user

    return _dependency


def current_refresh_token(request: Request) -> str | None:
    """Read the refresh-token cookie (JWT strategy), or None if missing."""
    return request.cookies.get(REFRESH_COOKIE_NAME)
