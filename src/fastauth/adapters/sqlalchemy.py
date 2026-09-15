"""SQLAlchemy adapter for FastAuth."""

from sqlalchemy.ext.asyncio import AsyncSession

from fastauth.adapters.adapters import Adapters
from fastauth.models import FastAuthSessionMixin, FastAuthUserMixin


class SQLAlchemyAdapter(Adapters):
    """Auth DB ops against the developer's own User/Session models.

    Never commits; only adds/flushes. The caller owns the transaction.
    One instance per request.
    """

    def __init__(
        self,
        db_session: AsyncSession,
        user_model: type[FastAuthUserMixin],
        session_model: type[FastAuthSessionMixin],
    ):
        """Bind a request session plus the app's User/Session models."""
        super().__init__(db_session, user_model, session_model)
