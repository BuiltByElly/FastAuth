"""OIDC login/callback routes — mounted on OIDCAuth.router.

Login: generate state, redirect to provider.
Callback: verify state, exchange code, resolve user, issue credentials
via the same adapter method SessionAuth/JWTAuth's own login route uses.
"""

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
from fastapi.responses import RedirectResponse

from fastauth.adapters.exceptions import EmailAlreadyRegistered
from fastauth.cookies import (
    refresh_cookie_kwargs,
    session_cookie_kwargs,
    set_refresh_cookie,
    set_session_cookie,
)
from fastauth.routes.context import OIDCContext
from fastauth.schemas import TokenResponse


def register_oidc_routes(router: APIRouter, ctx: OIDCContext) -> None:
    state_cookie_name = "fastauth_oidc_state"
    cookies = ctx.config.cookies

    DependsSession = Depends(ctx.db_session_dependency)
    DependsLoginLimit = Depends(ctx.rate_limiter.limit_for("/{provider}/login"))
    DependsCallbackLimit = Depends(ctx.rate_limiter.limit_for("/{provider}/callback"))

    @router.get("/{provider}/login", dependencies=[DependsLoginLimit])
    async def oidc_login(provider: str, request: Request):
        try:
            oidc_provider = ctx.get_provider(provider)
        except KeyError as e:
            raise HTTPException(404, str(e)) from None

        raw_state, signed = ctx.state_manager.generate(provider)
        redirect_uri = str(request.url_for("oidc_callback", provider=provider))
        auth_url = await oidc_provider.get_authorize_url(redirect_uri, raw_state)

        redirect = RedirectResponse(auth_url)
        redirect.set_cookie(
            state_cookie_name,
            signed,
            httponly=True,
            secure=cookies.secure,
            samesite=cookies.samesite,
            path=cookies.path,
            domain=cookies.domain,
            max_age=300,
        )
        return redirect

    @router.get(
        "/{provider}/callback",
        name="oidc_callback",
        dependencies=[DependsCallbackLimit],
    )
    async def oidc_callback(
        provider: str,
        code: str,
        state: str,
        request: Request,
        response: Response,
        db_session: Annotated[Any, DependsSession],
        bg_tasks: BackgroundTasks,
    ):
        try:
            oidc_provider = ctx.get_provider(provider)
        except KeyError as e:
            raise HTTPException(404, str(e)) from None

        cookie_value = request.cookies.get(state_cookie_name)
        if not ctx.state_manager.verify(cookie_value, state, provider):
            raise HTTPException(400, "Invalid or expired state")
        response.delete_cookie(state_cookie_name)

        redirect_uri = str(request.url_for("oidc_callback", provider=provider))
        user_info = await oidc_provider.fetch_user_info(code, redirect_uri)

        adapter = ctx.build_adapter(db_session)
        account = await adapter.get_oidc_account(provider, user_info.provider_user_id)
        if account is None:
            try:
                user = await adapter.create_user_from_oidc(user_info)
            except EmailAlreadyRegistered:
                raise HTTPException(400, "Email already registered") from None
        else:
            user = await adapter.get_user_by_id(account.user_id)

        if user is None:
            # Orphaned account row (its user is gone): fail closed, never
            # resurrect or authenticate anything.
            raise HTTPException(401, "Account no longer exists.")
        if not user.is_active:  # type: ignore[attr-defined]
            raise HTTPException(403, "Account is inactive.")

        if ctx.strategy == "session":
            credentials = await adapter.issue_credential(user)
            await db_session.commit()

            expires_at = credentials.expires_at  # type:ignore
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=UTC)
            max_age = max(0, int((expires_at - datetime.now(UTC)).total_seconds()))
            set_session_cookie(
                response,
                str(credentials.id),  # type:ignore
                **session_cookie_kwargs(cookies, max_age=max_age),
            )

            # Run the after-login hook (fire and forget)
            bg_tasks.add_task(
                ctx.oidc_login_hooks["run_after_oidc_login"], user_info, request
            )
            return {"success": True, "message": "Logged in successfully"}

        access_token = str(await adapter.issue_credential(user))
        refresh_token = await adapter.issue_refresh_token(user)
        # Persist user/account/refresh rows — without this the minted token
        # resolves to nothing and the IdP sign-in is lost on session close.
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
        bg_tasks.add_task(
            ctx.oidc_login_hooks["run_after_oidc_login"], user_info, request
        )
        return TokenResponse(access_token=access_token)
