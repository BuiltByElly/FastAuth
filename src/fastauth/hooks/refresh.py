import logging
from collections.abc import Awaitable, Callable

from fastapi import Request

logger = logging.getLogger("fastauth")


TokenReuseHandler = Callable[[str, Request], Awaitable[None]]


class RefreshHooks:
    """Holds and runs the handler attached to the refresh route's hook.

    Attach handlers with ``on_token_reuse_detected``. The refresh
    route calls ``run_token_reuse_detected`` once it has revoked the token family.
    """

    def __init__(self) -> None:
        self._token_reuse_detected: list[TokenReuseHandler] = []

    def on_token_reuse_detected(self, fn: TokenReuseHandler) -> TokenReuseHandler:
        """Register an observer that runs when refresh-token reuse is detected.

        Receives a str(user.id) event and the ``Request``, and returns
        nothing. It cannot change the response. Exceptions are logged to the
        ``fastauth`` logger and ignored.

        Args:
            fn: An async function ``(user_id: str, request: Request) -> None``.

        Returns:
            ``fn`` unchanged, so decorator use keeps the original function.
        """
        self._token_reuse_detected.append(fn)
        return fn

    async def run_token_reuse_detected(self, user_id: str, request: Request) -> None:
        """Run every ``on_token_reuse_detected`` handler in order. Never raises.

        Args:
            user_id: The affected user's id.
            request: The incoming FastAPI request. Handlers should treat it as
                read-only.
        """
        for fn in self._token_reuse_detected:
            try:
                await fn(user_id, request)
            except Exception:
                logger.exception(
                    "HOOK_ERROR: `on_token_reuse_detected`'s handler `%s` crashed",
                    fn.__name__,
                )
