"""Shared types with no dependencies on config.py or schemas.py —
exists specifically to avoid circular imports between the two.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class OAuthUserInfo:
    provider: str
    provider_user_id: str
    email: str | None
    email_verified: bool
    name: str | None
    avatar_url: str | None
    others: dict[str, Any] | None = None


@dataclass
class OAuth2LoginResult:
    user_info: OAuthUserInfo
    access_token: str
    refresh_token: str | None
    expires_at: datetime | None
