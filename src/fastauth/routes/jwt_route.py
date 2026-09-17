"""JWT-strategy routes: stateless access tokens, rotating refresh cookies."""

from collections.abc import Awaitable, Callable
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.cookies import (
    REFRESH_COOKIE_NAME,
    clear_refresh_cookie,
    set_refresh_cookie,
)
from fastauth.models import FastAuthUserMixin
from fastauth.routes.context import AuthContext
from fastauth.schemas import LoginRequest, TokenResponse
from fastauth.security import DUMMY_PASSWORD_HASH, verify_password


def register_jwt_routes(
    router: APIRouter,
    ctx: AuthContext,
    current_user: Callable[..., Awaitable[FastAuthUserMixin]],
) -> None:
    """Mount signup/login/refresh/logout/me using signed JWTs vía the adapter.

    Access tokens travel in the ``Authorization`` header; refresh tokens
    live in an HttpOnly cookie and rotate single-use (reuse revokes the
    whole refresh family).
    """
    SignupRequest = ctx.signup_schema
    UserResponse = ctx.user_response_schema
    DependsSession = Depends(ctx.db_session_dependency)

    @router.post("/signup", response_model=UserResponse)
    async def signup(
        payload: SignupRequest,  # type: ignore[valid-type]
        session: Annotated[AsyncSession, DependsSession],
    ):
        """Create a user unless the email is taken."""
        adapter = ctx.build_adapter(session)
        if await adapter.get_user_by_email(payload.email):  # type: ignore[attr-defined]
            raise HTTPException(status_code=400, detail="Email already registered.")
        user = await adapter.create_user(payload.model_dump())
        await session.commit()
        return user

    @router.post("/login", response_model=TokenResponse)
    async def login(
        payload: LoginRequest,
        response: Response,
        session: Annotated[AsyncSession, DependsSession],
    ):
        """Verify credentials; return access token, set refresh cookie."""
        adapter = ctx.build_adapter(session)
        user = await adapter.get_user_by_email(payload.email)
        if user is None:
            verify_password(payload.password, DUMMY_PASSWORD_HASH)
            raise HTTPException(status_code=401, detail="Invalid credentials.")
        if not verify_password(payload.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid credentials.")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is inactive.")
        access_token = str(await adapter.issue_credential(user))
        refresh_token = await adapter.issue_refresh_token(user)
        await session.commit()
        set_refresh_cookie(
            response,
            refresh_token,
            max_age=ctx.jwt_config.refresh_token_expire_days * 24 * 60 * 60,  # type: ignore[union-attr]
        )
        return TokenResponse(access_token=access_token)

    @router.post("/refresh", response_model=TokenResponse)
    async def refresh(
        response: Response,
        request: Request,
        session: Annotated[AsyncSession, DependsSession],
    ):
        """Rotate the refresh cookie: burn it, issue a fresh pair.

        Reusing an already-rotated token revokes the whole refresh
        family (theft defense) — the user must log in again.
        """
        token = request.cookies.get(REFRESH_COOKIE_NAME)
        if token is None:
            raise HTTPException(status_code=401, detail="Missing refresh token.")
        adapter = ctx.build_adapter(session)
        user = await adapter.consume_refresh_token(token)
        if user is None:
            # Consume may have burned a row or revoked a stolen family:
            # those writes must survive the 401, so commit before raising.
            await session.commit()
            raise HTTPException(
                status_code=401, detail="Invalid or expired refresh token."
            )
        access_token = str(await adapter.issue_credential(user))
        refresh_token = await adapter.issue_refresh_token(user)
        await session.commit()
        set_refresh_cookie(
            response,
            refresh_token,
            max_age=ctx.jwt_config.refresh_token_expire_days * 24 * 60 * 60,  # type: ignore[union-attr]
        )
        return TokenResponse(access_token=access_token)

    @router.post("/logout")
    async def logout(
        response: Response,
        request: Request,
        session: Annotated[AsyncSession, DependsSession],
    ):
        """Revoke the refresh cookie's token and clear the cookie."""
        token = request.cookies.get(REFRESH_COOKIE_NAME)
        if token is None:
            raise HTTPException(status_code=401, detail="Missing refresh token.")
        adapter = ctx.build_adapter(session)
        await adapter.revoke_refresh_token(token)
        await session.commit()
        clear_refresh_cookie(response)
        return {"message": "logged out"}

    @router.get("/me", response_model=UserResponse)
    async def me(
        session: Annotated[AsyncSession, DependsSession],
        current_user: Annotated[FastAuthUserMixin, Depends(current_user)],
    ):
        """Return the user behind the bearer token."""
        user = current_user
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid token.")
        return user
