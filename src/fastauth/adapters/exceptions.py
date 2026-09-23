import uuid


class RefreshTokenReused(Exception):
    """Raised when an already-consumed refresh token is presented again.

    The caller (the refresh route) is responsible for firing
    ``on_token_reuse_detected`` — the adapter only detects and revokes.
    """

    def __init__(self, user_id: uuid.UUID):
        self.user_id = user_id
        super().__init__(f"Refresh token reuse detected for user {user_id}")
