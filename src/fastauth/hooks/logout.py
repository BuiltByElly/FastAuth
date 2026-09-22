import logging
from collections.abc import Awaitable, Callable

from pydantic import BaseModel

LogoutHandler = Callable[[BaseModel], Awaitable[None]]

logger = logging.getLogger("fastauth")


class LogoutHooks:
    def __init__(
        self,
    ):
        self._after_logout: list[LogoutHandler] = []

    def add_after_logout(self, fn: LogoutHandler):
        """Register an observer that runs after a successful logout.

        Receives a ``User``, and returns nothing.
        It cannot change the response. Exceptions are logged to the ``fastauth`` logger and ignored.

        Args:
            fn: An async function ``(user: type[BaseModel]) -> None``.

        Returns:
            ``fn`` unchanged, so decorator use keeps the original function.
        """
        self._after_logout.append(fn)
        return fn

    async def run_after_logout(self, user: BaseModel):
        """Run every ``on_after_logout`` handler in order. Never raises.

        Args:
            user: The user object. Validated with UserResponse.
        """
        for fn in self._after_logout:
            try:
                await fn(user)

            except Exception as e:
                logger.exception(
                    "HOOK_ERROR: `on_after_logout`'s handler `%s` crashed.",
                    fn.__name__,
                    exc_info=e,
                )
