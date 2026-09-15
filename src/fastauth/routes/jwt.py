"""JWT-strategy routes: stateless placeholder tokens (no session rows)."""

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.routes.context import AuthContext, bearer_token
from fastauth.schemas import LoginRequest, TokenResponse
from fastauth.security import verify_password

# Placeholders until real JWT config lands on FastAuth.
JWT_SECRET = "change-me"
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_MINUTES = 60


def register_jwt_routes(router: APIRouter, ctx: AuthContext) -> None:
    """Mount signup/login/refresh/me using placeholder tokens vía the adapter.

    Token signing currently uses a stand-in scheme (see adapter); wire
    JWT_SECRET/JWT_ALGORITHM/JWT_EXPIRE_MINUTES into real signing here next.
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
        session: Annotated[AsyncSession, DependsSession],
    ):
        """Verify credentials and mint a token (TODO: sign with JWT_*)."""
        adapter = ctx.build_adapter(session)
        user = await adapter.get_user_by_email(payload.email)
        if user is None or not verify_password(payload.password, user.hashed_password):
            raise HTTPException(status_code=401, detail="Invalid credentials.")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="Account is inactive.")
        await session.commit()
        # TODO: replace adapter placeholder with real JWT:
        # jwt.encode({...}, JWT_SECRET, algorithm=JWT_ALGORITHM,
        #            expires_in=timedelta(minutes=JWT_EXPIRE_MINUTES))
        return TokenResponse(access_token=str(await adapter.issue_credential(user)))

    @router.post("/refresh", response_model=TokenResponse)
    async def refresh(
        session: Annotated[AsyncSession, DependsSession],
        authorization: Annotated[str | None, Header()] = None,
    ):
        """Re-issue a token for a still-valid one (TODO: real JWT verify)."""
        token = bearer_token(authorization)
        adapter = ctx.build_adapter(session)
        user = await adapter.resolve_credential(token or "")
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid token.")
        return TokenResponse(access_token=str(await adapter.issue_credential(user)))

    @router.get("/me", response_model=UserResponse)
    async def me(
        session: Annotated[AsyncSession, DependsSession],
        authorization: Annotated[str | None, Header()] = None,
    ):
        """Return the user behind the bearer token."""
        token = bearer_token(authorization)
        user = await ctx.build_adapter(session).resolve_credential(token or "")
        if user is None:
            raise HTTPException(status_code=401, detail="Invalid token.")
        return user
