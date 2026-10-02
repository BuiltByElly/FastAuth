import logging
from collections.abc import Awaitable, Callable

from fastapi import Request

from fastauth.hooks.models import PasswordChanged, PasswordResetRequested

logger = logging.getLogger("fastauth")


PasswordResetHandler = Callable[[PasswordResetRequested, Request], Awaitable[None]]
PasswordChangedHandler = Callable[[PasswordChanged, Request], Awaitable[None]]


class PasswordHooks:
    """Holds and runs the handlers attached to the password-reset hooks.

    Both hooks are observers: they cannot block the request or modify
    anything, and a handler crash is logged and ignored.
    """

    def __init__(self) -> None:
        self._reset_requested: list[PasswordResetHandler] = []
        self._password_changed: list[PasswordChangedHandler] = []

    def on_password_reset_requested(
        self, fn: PasswordResetHandler
    ) -> PasswordResetHandler:
        """Register a handler that runs when a password reset is requested.

        Receives a ``PasswordResetRequested`` event and the ``Request``. This
        is where you send the token to the user (email, SMS, etc.) — FastAuth
        does not send anything itself. Do not ``await`` slow delivery work
        inline if you can help it; this already runs in the background, after
        the response has been sent, so timing here doesn't affect the client.

        Args:
            fn: An async function ``(event: PasswordResetRequested, request: Request) -> None``.

        Returns:
            ``fn`` unchanged, so decorator use keeps the original function.
        """
        self._reset_requested.append(fn)
        return fn

    def on_password_changed(self, fn: PasswordChangedHandler) -> PasswordChangedHandler:
        """Register a handler that runs after a password reset completes.

        Receives a ``PasswordChanged`` event and the ``Request``. Useful for
        "your password was changed" notification emails and audit logging.

        Args:
            fn: An async function ``(event: PasswordChanged, request: Request) -> None``.

        Returns:
            ``fn`` unchanged, so decorator use keeps the original function.
        """
        self._password_changed.append(fn)
        return fn

    async def run_password_reset_requested(
        self, event: PasswordResetRequested, request: Request
    ) -> None:
        """Run every ``on_password_reset_requested`` handler in order. Never raises."""
        for fn in self._reset_requested:
            try:
                await fn(event, request)
            except Exception as e:
                logger.exception(
                    "HOOK_ERROR: `on_password_reset_requested`'s handler `%s` crashed",
                    fn.__name__,
                    exc_info=e,
                )

    async def run_password_changed(
        self, event: PasswordChanged, request: Request
    ) -> None:
        """Run every ``on_password_changed`` handler in order. Never raises."""
        for fn in self._password_changed:
            try:
                await fn(event, request)
            except Exception as e:
                logger.exception(
                    "HOOK_ERROR: `on_password_changed`'s handler `%s` crashed",
                    fn.__name__,
                    exc_info=e,
                )
