"""Session-strategy routes: DB-backed session rows, cookie transport."""

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import (
    APIRouter,
    BackgroundTasks,
    Depends,
    HTTPException,
    Request,
    Response,
)
from fastapi.responses import JSONResponse

from fastauth.cookies import (
    clear_cookie_kwargs,
    clear_session_cookie,
    session_cookie_kwargs,
    set_session_cookie,
)
from fastauth.hooks.login import LoginFailure
from fastauth.protocols import UserProtocol
from fastauth.routes.context import AuthContext
from fastauth.security import DUMMY_PASSWORD_HASH, verify_password


def register_session_routes(
    router: APIRouter,
    ctx: AuthContext,
    current_user: Callable[..., Awaitable[UserProtocol]],
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
        db_session: Annotated[Any, DependsSession],
        response: Response,
        request: Request,
        bg_tasks: BackgroundTasks,
    ):
        """Create a user unless the email is taken."""

        # Before signup, run the `run_before_signup` hook -> validated payload
        payload = await ctx.signup_hooks["run_before_signup"](payload, request)

        adapter = ctx.build_adapter(db_session)
        if await adapter.get_user_by_email(payload.email):  # type: ignore[attr-defined]
            bg_tasks.add_task(
                ctx.signup_hooks["run_signup_failure"],
                "User's email already exists",
                request,
            )
            return JSONResponse(
                {"detail": "Email already registered"},
                status_code=400,
                background=bg_tasks,
            )
        try:
            user = await adapter.create_user(payload.model_dump())
            record: Any = await adapter.issue_credential(user)
            await db_session.commit()
            expires_at = record.expires_at
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            max_age = max(0, int((expires_at - datetime.now(UTC)).total_seconds()))
            set_session_cookie(
                response,
                str(record.id),
                **session_cookie_kwargs(cookies, max_age=max_age),
            )

            # Run the after-signup hook (fire and forget)
            user_out = UserResponse.model_validate(user)
            bg_tasks.add_task(ctx.signup_hooks["run_after_signup"], user_out, request)  # type:ignore
            return user
        except Exception as e:
            await db_session.rollback()
            bg_tasks.add_task(ctx.signup_hooks["run_signup_failure"], str(e), request)
            raise

    @router.post("/login", dependencies=[DependsLoginLimit])
    async def login(
        payload: LoginRequest,  # type: ignore[valid-type]
        response: Response,
        request: Request,
        db_session: Annotated[Any, DependsSession],
        bg_tasks: BackgroundTasks,
    ):
        """Verify credentials, rotate any existing session, issue a new one."""

        # Before login, run the `run_before_login` hook -> validated payload
        payload = await ctx.login_hooks["run_before_login"](payload, request)

        adapter = ctx.build_adapter(db_session)
        user = await adapter.get_user_by_email(payload.email)

        # Run the login failure hook (fire and forget)
        if user is None:
            verify_password(payload.password, DUMMY_PASSWORD_HASH, hasher)
            bg_tasks.add_task(
                ctx.login_hooks["run_login_failure"],
                LoginFailure(user_id=None, error="User not found"),
                request,
            )
            return JSONResponse(
                {"detail": "Invalid credentials."},
                status_code=401,
                background=bg_tasks,
            )

        if not verify_password(payload.password, user.hashed_password, hasher):
            bg_tasks.add_task(
                ctx.login_hooks["run_login_failure"],
                # user_id stays None even though the account exists: failure
                # observers must not become an account-enumeration oracle.
                LoginFailure(user_id=None, error="Invalid credentials."),
                request,
            )
            return JSONResponse(
                {"detail": "Invalid credentials."},
                status_code=401,
                background=bg_tasks,
            )

        if not user.is_active:
            bg_tasks.add_task(
                ctx.login_hooks["run_login_failure"],
                LoginFailure(user_id=str(user.id), error="Account is inactive."),
                request,
            )
            return JSONResponse(
                {"detail": "Account is inactive."},
                status_code=403,
                background=bg_tasks,
            )

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

        # Run the after-login hook (fire and forget)
        user_out = UserResponse.model_validate(user)
        bg_tasks.add_task(ctx.login_hooks["run_after_login"], user_out, request)  # type:ignore
        return {"success": True, "message": "Logged in successfully"}

    @router.post("/logout")
    async def logout(
        response: Response,
        request: Request,
        db_session: Annotated[Any, DependsSession],
        bg_tasks: BackgroundTasks,
    ):
        """Revoke the cookie (or bearer) session id and clear the cookie."""
        token = request.cookies.get(cookies.session_cookie_name)
        if token is None:
            raise HTTPException(status_code=401, detail="Missing session.")
        user_id = await ctx.build_adapter(db_session).revoke_credential(token)
        if user_id is not None:
            bg_tasks.add_task(ctx.logout_hooks["run_after_logout"], user_id)
        await db_session.commit()
        clear_session_cookie(
            response, name=cookies.session_cookie_name, **clear_cookie_kwargs(cookies)
        )

        return {"success": True, "message": "logged out"}

    @router.get("/me", response_model=UserResponse, dependencies=[DependsGeneral])
    async def me(
        current_user: Annotated[UserProtocol, Depends(current_user)],
    ):
        """Return the user behind the cookie (or bearer) session id."""
        return current_user
