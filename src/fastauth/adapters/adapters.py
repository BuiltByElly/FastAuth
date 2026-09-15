"""Per-request database bridge for FastAuth."""

from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.models import FastAuthSessionMixin, FastAuthUserMixin


class Adapters:
    """Base adapter. Wraps one request-scoped session."""

    def __init__(
        self,
        db_session: AsyncSession,
        user_model: type[FastAuthUserMixin],
        session_model: type[FastAuthSessionMixin],
    ):
        """Store the request-scoped session (no commit here)."""
        self.db_session = db_session
        self.user_model = user_model
        self.session_model = session_model
