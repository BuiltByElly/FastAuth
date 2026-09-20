"""Session-strategy routes: DB-backed session rows, cookie transport."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.cookies import (
    clear_cookie_kwargs,
    clear_session_cookie,
    session_cookie_kwargs,
    set_session_cookie,
)
from fastauth.models import FastAuthUserMixin
from fastauth.routes.context import AuthContext
from fastauth.security import DUMMY_PASSWORD_HASH, verify_password


def register_session_routes(
    router: APIRouter,
    ctx: AuthContext,
    current_user: Callable[..., Awaitable[FastAuthUserMixin]],
) -> None:
    """Mount signup/login/logout/me using session rows vía the adapter."""
    SignupRequest = ctx.signup_schema
    LoginRequest = ctx.login_schema
    UserResponse = ctx.user_response_schema
    DependsSession = Depends(ctx.db_session_dependency)
    cookies = ctx.config.cookies
    hasher = ctx.password_hasher
    DependsSignupLimit = Depends(ctx.rate_limiter.limit_for("/signup"))
    DependsLoginLimit = Depends(ctx.rate_limiter.limit_for("/login"))
    DependsGeneral = Depends(ctx.rate_limiter.limit())

    @router.post(
        "/signup", response_model=UserResponse, dependencies=[DependsSignupLimit]
    )
    async def signup(
        payload: SignupRequest,  # type: ignore[valid-type]
        db_session: Annotated[AsyncSession, DependsSession],
        response: Response,
        request: Request,
    ):
        """Create a user unless the email is taken."""

        # Before signup, run the `run_before_signup` hook -> validated payload
        payload = await ctx.signup_hooks["run_before_signup"](payload, request)

        adapter = ctx.build_adapter(db_session)
        if await adapter.get_user_by_email(payload.email):  # type: ignore[attr-defined]
            raise HTTPException(status_code=400, detail="Email already registered.")
        user = await adapter.create_user(payload.model_dump())
        record: Any = await adapter.issue_credential(user)
        await db_session.commit()
        expires_at = record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        max_age = max(0, int((expires_at - datetime.now(UTC)).total_seconds()))
        set_session_cookie(
            response, str(record.id), **session_cookie_kwargs(cookies, max_age=max_age)
        )
        await db_session.commit()
        return user

    @router.post("/login", dependencies=[DependsLoginLimit])
    async def login(
        payload: LoginRequest,  # type: ignore[valid-type]
        response: Response,
        request: Request,
        db_session: Annotated[AsyncSession, DependsSession],
    ):
        """Verify credentials, rotate any existing session, issue a new one."""
        adapter = ctx.build_adapter(db_session)
        user = await adapter.get_user_by_email(payload.email)
        if user is None:
            verify_password(payload.password, DUMMY_PASSWORD_HASH, hasher)
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        if not verify_password(payload.password, user.hashed_password, hasher):
            raise HTTPException(status_code=401, detail="Invalid credentials.")

        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is inactive.")

        old_token = request.cookies.get(cookies.session_cookie_name)

        if old_token is not None:
            await adapter.revoke_credential(old_token)

        record: Any = await adapter.issue_credential(user)
        await db_session.commit()
        expires_at = record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        max_age = max(0, int((expires_at - datetime.now(UTC)).total_seconds()))
        set_session_cookie(
            response, str(record.id), **session_cookie_kwargs(cookies, max_age=max_age)
        )
        return {"success": True, "message": "Logged in successfully"}

    @router.post("/logout")
    async def logout(
        response: Response,
        request: Request,
        db_session: Annotated[AsyncSession, DependsSession],
        current_user: Annotated[FastAuthUserMixin, Depends(current_user)],
    ):
        """Revoke the cookie (or bearer) session id and clear the cookie."""
        token = request.cookies.get(cookies.session_cookie_name)
        if token is None:
            raise HTTPException(status_code=401, detail="Missing session.")
        await ctx.build_adapter(db_session).revoke_credential(token)
        await db_session.commit()
        clear_session_cookie(
            response, name=cookies.session_cookie_name, **clear_cookie_kwargs(cookies)
        )
        return {"success": True, "message": "logged out"}

    @router.get("/me", response_model=UserResponse, dependencies=[DependsGeneral])
    async def me(
        current_user: Annotated[FastAuthUserMixin, Depends(current_user)],
    ):
        """Return the user behind the cookie (or bearer) session id."""
        return current_user
