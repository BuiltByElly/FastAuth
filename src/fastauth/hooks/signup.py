import logging
from collections.abc import Awaitable, Callable

from fastapi import HTTPException, Request
from pydantic import BaseModel

from fastauth.hooks.exceptions import HookAbort

logger = logging.getLogger("fastauth")

SignupHandler = Callable[[BaseModel, Request], Awaitable[BaseModel]]
SignupSuccessHandler = Callable[[BaseModel, Request], Awaitable[None]]
SignupFailureHandler = Callable[[str, Request], Awaitable[None]]


class SignupHooks:
    """Holds and runs the handlers attached to the signup hooks.

    Developers attach handlers with ``on_before_signup``. The signup route then
    calls ``run_before_signup`` to run them in order.

    Args:
        schema: The signup request model built at startup. Handlers
            receive instances of it, and every result is re-validated against it.
    """

    def __init__(self, schema: type[BaseModel]):
        self._before_signup: list[
            SignupHandler
        ] = []  # List of handlers to run before signup

        self._after_signup: list[
            SignupSuccessHandler
        ] = []  # List of handlers to run after signup

        self._signup_failure: list[
            SignupFailureHandler
        ] = []  # List of handlers to run after signup fails

        self._schema = (
            schema  # Schema for the signup request payload (used for _before hooks)
        )

    def on_before_signup(self, fn: SignupHandler) -> SignupHandler:
        """Register a handler that runs before a user is created.

        Handlers run in registration order. Each receives the current payload
        (an instance of the signup request schema) and the ``Request``, and must
        return the payload, modified or not. Raise ``HookAbort(status_code, detail)``
        to stop signup with that error. Any other exception is logged to the
        ``fastauth`` logger and returns a 500. Can be used as a decorator.

        Args:
            fn: An async function ``(payload: type[BaseModel], request:Request) -> payload``.

        Returns:
            ``fn`` unchanged, so decorator use keeps the original function.
        """
        self._before_signup.append(fn)
        return fn  # returning fn makes it work as a decorator

    def on_after_signup(self, fn: SignupSuccessHandler) -> SignupSuccessHandler:
        """Register an observer that runs after a successful signup.

        Receives a ``User`` (an instance of the response schema) and the ``Request``, and returns nothing.
        It cannot change the response. Exceptions are logged to the ``fastauth`` logger and ignored.

        Args:
            fn: An async function ``(user: type[BaseModel], request: Request) -> None``.

        Returns:
            ``fn`` unchanged, so decorator use keeps the original function.
        """
        self._after_signup.append(fn)
        return fn  # returning fn makes it work as a decorator

    def on_signup_failure(self, fn: SignupFailureHandler) -> SignupFailureHandler:
        """Register an observer that runs after a failed signup.

        Receives an error message and the ``Request``, and returns nothing.
        It cannot change the response. Exceptions are logged to the ``fastauth`` logger and ignored.

        Args:
            fn: An async function ``(error: str, request: Request) -> None``.

        Returns:
            ``fn`` unchanged, so decorator use keeps the original function.
        """
        self._signup_failure.append(fn)
        return fn  # returning fn makes it work as a decorator

    async def run_before_signup(self, payload: BaseModel, request: Request):
        """Run every ``on_before_signup`` handler in order.

        Each handler receives the payload returned by the previous one. The result
        is type-checked and re-validated against the request schema before the
        next handler runs.

        Args:
            payload: The validated signup request.
            request: The incoming FastAPI request. Handlers should treat it as
                read-only.

        Returns:
            The payload after all handlers have run.
        """
        for fn in self._before_signup:
            try:
                result = await fn(payload, request)
            except HookAbort:
                raise  # intentional block, pass through
            except Exception:
                logger.exception(
                    "HOOK_ERROR: `on_before_signup`'s handler `%s` crashed", fn.__name__
                )
                raise HTTPException(500, "Internal error")
            if not isinstance(result, self._schema):
                logger.error(
                    "HOOK_ERROR: `on_before_signup`'s handler `%s` must return a value of type `%s`",
                    fn.__name__,
                    self._schema.__name__,
                )
                raise HTTPException(500, "Internal error")
            payload = self._schema.model_validate(
                result.model_dump()
            )  # the next handler sees the updated payload
        return payload

    async def run_after_signup(self, user: BaseModel, request: Request):
        """Run every ``on_after_signup`` handler in order. Never raises.

        Args:
            user: The user object. Validated with UserResponse.
            request: The incoming FastAPI request. Handlers should treat it as
                read-only.
        """
        for fn in self._after_signup:
            try:
                await fn(user, request)

            except Exception:
                logger.exception(
                    "HOOK_ERROR: `on_after_signup`'s handler `%s` crashed", fn.__name__
                )

    async def run_signup_failure(self, error: str, request: Request):
        """Run every ``on_signup_failure`` handler in order. Never raises.

        Args:
            error: The error message.
            request: The incoming FastAPI request. Handlers should treat it as
                read-only.
        """
        for fn in self._signup_failure:
            try:
                await fn(error, request)
            except Exception:
                logger.exception(
                    "HOOK_ERROR: `on_signup_failure`'s handler `%s` crashed",
                    fn.__name__,
                )
