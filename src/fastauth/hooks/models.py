from pydantic import BaseModel, ConfigDict


class PasswordResetRequested(BaseModel):
    """What ``on_password_reset_requested`` handlers receive.

    Fired when a reset was requested for an existing account. The dev's
    handler is responsible for actually sending the token somewhere
    (email, SMS, etc.) — FastAuth only generates and stores it.

    Never fired for unknown emails, so a handler receiving this event
    already knows the account exists — don't leak that fact back to
    the client from inside a handler.
    """

    model_config = ConfigDict(frozen=True)
    user_id: str
    email: str
    token: str


class PasswordChanged(BaseModel):
    """What ``on_password_changed`` handlers receive, after a reset completes."""

    model_config = ConfigDict(frozen=True)
    user_id: str


class LoginFailure(BaseModel):
    model_config = ConfigDict(frozen=True)
    user_id: str | None  # None if the account doesn't exist
    error: str
