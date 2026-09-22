import logging
from collections.abc import Awaitable, Callable
from typing import Literal

from fastapi import HTTPException, Request
from pydantic import BaseModel, ConfigDict, EmailStr

from fastauth.hooks.exceptions import HookAbort

logger = logging.getLogger("fastauth")


class LoginFailure(BaseModel):
    model_config = ConfigDict(frozen=True)
    user_id: str | None  # None if the account doesn't exist
    error: str


LoginHandler = Callable[[BaseModel, Request], Awaitable[BaseModel]]  # before: may block
LoginFailureHandler = Callable[[LoginFailure, Request], Awaitable[None]]  # observer
LoginSuccessHandler = Callable[[BaseModel, Request], Awaitable[None]]  # observer


class LoginHooks:
    """Holds and runs the handlers attached to the login route's hooks.

    Hooks:
        ``on_before_login``: may modify the payload or block with ``HookAbort``.
        ``on_login_failure``: observer, runs after a failed login.
        ``on_after_login``: observer, runs after a successful login.

    Args:
        schema: The login request model. ``before`` handlers receive
            instances of it, and every result is re-validated against it.
    """

    def __init__(self, schema: type[BaseModel]):
        self._schema = schema
        self._before_login: list[LoginHandler] = []
        self._login_failure: list[LoginFailureHandler] = []
        self._after_login: list[LoginSuccessHandler] = []

    # ---- registration (usable as decorators) ----

    def on_before_login(self, fn: LoginHandler) -> LoginHandler:
        """Register a handler that runs before credentials are checked.

        Receives the payload and the ``Request``, and must return the payload,
        modified or not. Raise ``HookAbort(status_code, detail)`` to stop the
        login. Any other exception is logged and returns a 500.
        """
        self._before_login.append(fn)
        return fn

    def on_login_failure(self, fn: LoginFailureHandler) -> LoginFailureHandler:
        """Register an observer that runs after a failed login.

        Receives a ``LoginFailure`` and the ``Request``, and returns nothing.
        It cannot change the response. Exceptions are logged and ignored.
        """
        self._login_failure.append(fn)
        return fn

    def on_after_login(self, fn: LoginSuccessHandler) -> LoginSuccessHandler:
        """Register an observer that runs after a successful login.

        Receives the user (an instance of the response schema) and the
        ``Request``, and returns nothing. Exceptions are logged and ignored.
        """
        self._after_login.append(fn)
        return fn

    # ---- running ----

    async def run_before_login(self, payload: BaseModel, request: Request) -> BaseModel:
        """Run every ``on_before_login`` handler in order.

        Each handler receives the payload returned by the previous one, which is
        re-validated against the request schema first.

        Raises:
            HookAbort: A handler intentionally blocked the login.
            HTTPException: 500, if a handler crashed or returned an invalid payload.
        """
        for fn in self._before_login:
            try:
                result = await fn(payload, request)
                payload = self._schema.model_validate(result.model_dump())
            except HookAbort:
                raise  # intentional block, pass through
            except Exception:
                logger.exception(
                    "HOOK_ERROR: `on_before_login` handler `%s` failed", fn.__name__
                )
                raise HTTPException(500, "Internal error")
        return payload

    async def run_login_failure(self, failure: LoginFailure, request: Request) -> None:
        """Notify every ``on_login_failure`` observer. Never raises."""
        await self._notify("on_login_failure", self._login_failure, failure, request)

    async def run_after_login(self, user: BaseModel, request: Request) -> None:
        """Notify every ``on_after_login`` observer. Never raises."""
        await self._notify("on_after_login", self._after_login, user, request)

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
