"""FastAuth: simple flexible auth for FastAPI."""

from .core import FastAuth, JWTAuth, OAuth2Auth, OIDCAuth, SessionAuth

__all__ = [
    "FastAuth",
    "JWTAuth",
    "OAuth2Auth",
    "OIDCAuth",
    "SessionAuth",
]
