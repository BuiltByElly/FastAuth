"""Session-strategy routes: DB-backed session rows."""

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.routes.context import AuthContext, bearer_token
from fastauth.schemas import LoginRequest, SessionResponse
from fastauth.security import verify_password


def register_session_routes(router: APIRouter, ctx: AuthContext) -> None:
    """Mount signup/login/logout/me using session rows vía the adapter."""
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

    @router.post("/login", response_model=SessionResponse)
    async def login(
        payload: LoginRequest,
        session: Annotated[AsyncSession, DependsSession],
    ):
        """Verify credentials and issue a session row."""
        adapter = ctx.build_adapter(session)
        user = await adapter.get_user_by_email(payload.email)
        if user is None or not verify_password(payload.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid credentials.")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is inactive.")
        record = await adapter.issue_credential(user)
        await session.commit()
        return SessionResponse(
            session_id=str(record.id), expires_at=record.expires_at.isoformat()
        )

    @router.post("/logout")
    async def logout(
        session: Annotated[AsyncSession, DependsSession],
        authorization: Annotated[str | None, Header()] = None,
    ):
        """Revoke the bearer session id."""
        token = bearer_token(authorization)
        if token is None:
            raise HTTPException(status_code=401, detail="Missing bearer token.")
        await ctx.build_adapter(session).revoke_credential(token)
        await session.commit()
        return {"message": "logged out"}

    @router.get("/me", response_model=UserResponse)
    async def me(
        session: Annotated[AsyncSession, DependsSession],
        authorization: Annotated[str | None, Header()] = None,
    ):
        """Return the user behind the bearer session id."""
        token = bearer_token(authorization)
        user = await ctx.build_adapter(session).resolve_credential(token or "")
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid or expired session.")
        return user
