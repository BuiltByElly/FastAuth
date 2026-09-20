import logging
from collections.abc import Awaitable, Callable

from fastapi import HTTPException, Request
from pydantic import BaseModel

from fastauth.hooks.exceptions import HookAbort

logger = logging.getLogger("fastauth")

SignupHandler = Callable[[BaseModel, Request], Awaitable[BaseModel]]


class SignUpHooks:
    """Holds and runs the handlers attached to the signup hooks.

    Developers attach handlers with ``on_before_signup``. The signup route then
    calls ``run_before_signup`` to run them in order.

    Args:
        request_schema: The signup request model built at startup. Handlers
            receive instances of it, and every result is re-validated against it.
        response_schema: The signup response model, reserved for the future
            ``after`` hooks. Not used yet.
    """

    def __init__(
        self, request_schema: type[BaseModel], response_schema: type[BaseModel]
    ):
        self._before_signup: list[
            SignupHandler
        ] = []  # List of handlers to run before signup
        self._request_schema = request_schema  # Schema for the signup request payload (used for _before hooks)
        self._response_schema = response_schema  # Schema for the signup response payload (used for _after hooks)

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

        Raises:
            HookAbort: A handler intentionally blocked the signup.
            HTTPException: 500, if a handler crashed or returned the wrong type.
        """
        for fn in self._before_signup:
            try:
                result = await fn(payload, request)
            except HookAbort:
                raise  # intentional block, pass through
            except Exception:
                logger.exception(
                    "HOOK_ERROR: on_before_signup handler `%s` crashed", fn.__name__
                )
                raise HTTPException(500, "Internal error")
            if not isinstance(result, self._request_schema):
                logger.error(
                    "HOOK_ERROR: handler `%s` must return a value of type `%s`",
                    fn.__name__,
                    self._request_schema.__name__,
                )
                raise HTTPException(500, "Internal error")
            payload = self._request_schema.model_validate(
                result.model_dump()
            )  # the next handler sees the updated payload
        return payload
