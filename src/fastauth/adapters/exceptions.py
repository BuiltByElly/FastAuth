import uuid


class RefreshTokenReused(Exception):
    """Raised when an already-consumed refresh token is presented again.

    The caller (the refresh route) is responsible for firing
    ``on_token_reuse_detected`` — the adapter only detects and revokes.
    """

    def __init__(self, user_id: uuid.UUID):
        self.user_id = user_id
        super().__init__(f"Refresh token reuse detected for user {user_id}")


class EmailAlreadyRegistered(Exception):
    """Raised when an OIDC email claim collides with an existing account.

    The caller (the OIDC callback route) maps this to a 400 so an IdP email
    claim can neither take over nor crash over a password account.
    """

    def __init__(self, email: str | None):
        self.email = email
        super().__init__(f"Email already registered: {email}")
