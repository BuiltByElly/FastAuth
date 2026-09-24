"""JWT-strategy routes: stateless access tokens, rotating refresh cookies."""

from collections.abc import Awaitable, Callable
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

from fastauth.adapters.exceptions import RefreshTokenReused
from fastauth.cookies import (
    clear_cookie_kwargs,
    clear_refresh_cookie,
    refresh_cookie_kwargs,
    set_refresh_cookie,
)
from fastauth.hooks.login import LoginFailure
from fastauth.routes.context import AuthContext
from fastauth.schemas import TokenResponse
from fastauth.security import DUMMY_PASSWORD_HASH, verify_password


def register_jwt_routes(
    router: APIRouter,
    ctx: AuthContext,
    current_user: Callable[..., Awaitable[Any]],
) -> None:
    """Mount signup/login/refresh/logout/me using signed JWTs vía the adapter.

    Access tokens travel in the ``Authorization`` header; refresh tokens
    live in an HttpOnly cookie and rotate single-use (reuse revokes the
    whole refresh family).
    """
    SignupRequest = ctx.signup_schema
    LoginRequest = ctx.login_schema
    UserResponse = ctx.user_response_schema
    DependsSession = Depends(ctx.db_session_dependency)
    cookies = ctx.config.cookies
    hasher = ctx.password_hasher
    DependsSignupLimit = Depends(ctx.rate_limiter.limit_for("/signup"))
    DependsLoginLimit = Depends(ctx.rate_limiter.limit_for("/login"))
    DependsRefreshLimit = Depends(ctx.rate_limiter.limit_for("/refresh"))
    DependsGeneral = Depends(ctx.rate_limiter.limit())

    @router.post(
        "/signup", response_model=TokenResponse, dependencies=[DependsSignupLimit]
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
            access_token = str(await adapter.issue_credential(user))
            refresh_token = await adapter.issue_refresh_token(user)
            await db_session.commit()
            set_refresh_cookie(
                response,
                refresh_token,
                **refresh_cookie_kwargs(
                    cookies,
                    max_age=ctx.config.jwt.refresh_token_expire_days * 24 * 60 * 60,  # type: ignore[union-attr]
                ),
            )
            # Run the after-signup hook (fire and forget)
            user_out = UserResponse.model_validate(user)
            bg_tasks.add_task(ctx.signup_hooks["run_after_signup"], user_out, request)  # type:ignore
            return TokenResponse(access_token=access_token)
        except Exception as e:
            await db_session.rollback()
            bg_tasks.add_task(ctx.signup_hooks["run_signup_failure"], str(e), request)
            raise

    @router.post(
        "/login", response_model=TokenResponse, dependencies=[DependsLoginLimit]
    )
    async def login(
        payload: LoginRequest,  # type: ignore[valid-type]
        response: Response,
        request: Request,
        db_session: Annotated[Any, DependsSession],
        bg_tasks: BackgroundTasks,
    ):
        """Verify credentials; return access token, set refresh cookie."""

        # Before login, run the `run_before_login` hook -> validated payload
        payload = await ctx.login_hooks["run_before_login"](payload, request)

        adapter = ctx.build_adapter(db_session)
        user = await adapter.get_user_by_email(payload.email)
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

        access_token = str(await adapter.issue_credential(user))
        refresh_token = await adapter.issue_refresh_token(user)

        await db_session.commit()
        set_refresh_cookie(
            response,
            refresh_token,
            **refresh_cookie_kwargs(
                cookies,
                max_age=ctx.config.jwt.refresh_token_expire_days * 24 * 60 * 60,  # type: ignore[union-attr]
            ),
        )

        # Run the after-login hook (fire and forget)
        user_out = UserResponse.model_validate(user)
        bg_tasks.add_task(ctx.login_hooks["run_after_login"], user_out, request)  # type:ignore
        return TokenResponse(access_token=access_token)

    @router.post(
        "/refresh", response_model=TokenResponse, dependencies=[DependsRefreshLimit]
    )
    async def refresh(
        response: Response,
        request: Request,
        db_session: Annotated[Any, DependsSession],
        bg_tasks: BackgroundTasks,
    ):
        """Rotate the refresh cookie: burn it, issue a fresh pair.

        Reusing an already-rotated token revokes the whole refresh
        family (theft defense) — the user must log in again.
        """
        token = request.cookies.get(cookies.refresh_cookie_name)
        if token is None:
            raise HTTPException(status_code=401, detail="Missing refresh token.")

        adapter = ctx.build_adapter(db_session)

        try:
            user = await adapter.consume_refresh_token(token)
        except RefreshTokenReused as e:
            # The adapter already revoked the family; that write must survive
            # the 401, so commit before returning.
            await db_session.commit()
            bg_tasks.add_task(
                ctx.refresh_hooks["run_token_reuse_detected"],
                str(e.user_id),
                request,
            )
            return JSONResponse(
                {"detail": "Invalid or expired refresh token."},
                status_code=401,
                background=bg_tasks,
            )

        if user is None:
            # Consume may have burned a row (expired/already-revoked cleanup):
            # that write must survive the 401, so commit before raising.
            await db_session.commit()
            raise HTTPException(
                status_code=401, detail="Invalid or expired refresh token."
            )

        access_token = str(await adapter.issue_credential(user))
        refresh_token = await adapter.issue_refresh_token(user)
        await db_session.commit()
        set_refresh_cookie(
            response,
            refresh_token,
            **refresh_cookie_kwargs(
                cookies,
                max_age=ctx.config.jwt.refresh_token_expire_days * 24 * 60 * 60,  # type: ignore[union-attr]
            ),
        )
        return TokenResponse(access_token=access_token)

    @router.post("/logout")
    async def logout(
        response: Response,
        request: Request,
        bg_tasks: BackgroundTasks,
        db_session: Annotated[Any, DependsSession],
    ):
        """Revoke the refresh cookie's token and clear the cookie."""
        token = request.cookies.get(cookies.refresh_cookie_name)
        if token is None:
            raise HTTPException(status_code=401, detail="Missing refresh token.")
        adapter = ctx.build_adapter(db_session)
        user_id = await adapter.revoke_refresh_token(token)
        if user_id is not None:
            bg_tasks.add_task(ctx.logout_hooks["run_after_logout"], user_id)
        await db_session.commit()
        clear_refresh_cookie(
            response, name=cookies.refresh_cookie_name, **clear_cookie_kwargs(cookies)
        )
        return {"message": "logged out"}

    @router.get("/me", response_model=UserResponse, dependencies=[DependsGeneral])
    async def me(
        current_user: Annotated[Any, Depends(current_user)],
    ):
        """Return the user behind the bearer token."""
        user = current_user
        if user is None:
            raise HTTPException(status_code=401, detail="Not authenticated.")
        return user
