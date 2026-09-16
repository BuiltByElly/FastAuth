"""Strategy route registrars."""

from fastauth.routes.jwt import register_jwt_routes
from fastauth.routes.session import register_session_routes

__all__ = ["register_jwt_routes", "register_session_routes"]
