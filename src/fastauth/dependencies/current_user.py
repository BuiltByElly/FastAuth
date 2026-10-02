"""
(Do not import directly)
Dev-facing `current_user` dependencies, one per strategy.

Build them from an `AuthContext` (normally via `auth.current_user`, which
picks the right one for the instance's strategy), or call the builders
directly. Use as `Depends(auth.current_user)` in your own routes.
"""

from collections.abc import Awaitable, Callable
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

# from fastauth.cookies import REFRESH_COOKIE_NAME
from fastauth.routes.context import AuthContext

# Shared bearer scheme (auto_error=False so we raise 401, not 403).
security = HTTPBearer(auto_error=False)


def session_current_user(
    ctx: AuthContext,
) -> Callable[..., Awaitable[Any]]:
    """Build a dependency resolving the user from the session cookie."""

    async def _dependency(
        request: Request,
        session: Annotated[Any, Depends(ctx.db_session_dependency)],
    ) -> Any:
        token = request.cookies.get(ctx.config.cookies.session_cookie_name)
        if token is None:
            raise HTTPException(status_code=401, detail="Missing session cookie.")
        user = await ctx.build_adapter(session).resolve_credential(token)
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid or expired session.")
        return user

    return _dependency


def jwt_current_user(ctx: AuthContext) -> Callable[..., Awaitable[Any]]:
    """Build a dependency resolving the user from the bearer access token."""

    async def _dependency(
        session: Annotated[Any, Depends(ctx.db_session_dependency)],
        credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    ) -> Any:
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
