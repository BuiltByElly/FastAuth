import logging
from collections.abc import Awaitable, Callable

from fastapi import Request
from pydantic import BaseModel

logger = logging.getLogger("fastauth")


LoginSuccessHandler = Callable[[BaseModel, Request], Awaitable[None]]  # observer


class OIDCLoginHooks:
    """Holds and runs the handlers attached to the login route's hooks.

    Hooks:
        ``on_before_login``: may modify the payload or block with ``HookAbort``.
        ``on_login_failure``: observer, runs after a failed login.
        ``on_after_login``: observer, runs after a successful login.

    Args:
        schema: The login request model. ``before`` handlers receive
            instances of it, and every result is re-validated against it.
    """

    def __init__(self):
        self._after_login: list[LoginSuccessHandler] = []

    # ---- registration (usable as decorators) ----

    def on_after_oidc_login(self, fn: LoginSuccessHandler) -> LoginSuccessHandler:
        """Register an observer to run after a successful login.

        Receives ``(user, request)``, where ``user`` is either the
        response-schema instance (password login) or the resolved
        ``OAuthUserInfo`` (OIDC login) — check which you got if your
        handler needs to branch on login method. Returns nothing.

        Runs as a background task after the response is sent and the DB
        transaction is committed — there is no request-scoped DB session
        available here, so open your own if you need to write anything.
        Raised exceptions are logged and otherwise ignored; they never
        affect the response already sent to the client.
        """
        self._after_login.append(fn)
        return fn

    # ---- running ----

    async def run_after_oidc_login(self, user: BaseModel, request: Request) -> None:
        """Notify every ``on_after_oidc_login`` observer. Never raises."""
        await self._notify("on_after_oidc_login", self._after_login, user, request)

    @staticmethod
    async def _notify(
        name: str, handlers: list, event: BaseModel, request: Request
    ) -> None:
        for fn in handlers:
            try:
                await fn(event, request)
            except Exception:  # observers can never break or block a login
                logger.exception(
                    "HOOK_ERROR: `%s` handler `%s` failed", name, fn.__name__
                )


class OAuth2LoginHooks:
    """Holds and runs the handlers attached to the login route's hooks.

    Hooks:
        ``on_before_login``: may modify the payload or block with ``HookAbort``.
        ``on_login_failure``: observer, runs after a failed login.
        ``on_after_login``: observer, runs after a successful login.

    Args:
        schema: The login request model. ``before`` handlers receive
            instances of it, and every result is re-validated against it.
    """

    def __init__(self):
        self._after_login: list[LoginSuccessHandler] = []

    # ---- registration (usable as decorators) ----

    def on_after_oauth2_login(self, fn: LoginSuccessHandler) -> LoginSuccessHandler:
        """Register an observer to run after a successful login.

        Receives ``(user, request)``, where ``user`` is either the
        response-schema instance (password login) or the resolved
        ``OAuthUserInfo`` (OAuth2 login) — check which you got if your
        handler needs to branch on login method. Returns nothing.

        Runs as a background task after the response is sent and the DB
        transaction is committed — there is no request-scoped DB session
        available here, so open your own if you need to write anything.
        Raised exceptions are logged and otherwise ignored; they never
        affect the response already sent to the client.
        """
        self._after_login.append(fn)
        return fn

    # ---- running ----

    async def run_after_oauth2_login(self, user: BaseModel, request: Request) -> None:
        """Notify every ``on_after_oauth2_login`` observer. Never raises."""
        await self._notify("on_after_oauth2_login", self._after_login, user, request)

    @staticmethod
    async def _notify(
        name: str, handlers: list, event: BaseModel, request: Request
    ) -> None:
        for fn in handlers:
            try:
                await fn(event, request)
            except Exception:  # observers can never break or block a login
                logger.exception(
                    "HOOK_ERROR: `%s` handler `%s` failed", name, fn.__name__
                )
