"""Auth configuration objects: validated settings, no I/O.

`JWTConfig` is the settings surface the JWT strategy consumes for token
signing. It carries no logic — just validated values so a weak/hardcoded
secret fails at startup instead of in production.
"""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

JwtAlgorithm = Literal["HS256", "HS384", "HS512"]


class JWTConfig(BaseModel):
    """Settings the JWT strategy signs and validates tokens with.

    Attributes:
        secret_key: HMAC secret. Minimum 32 chars; placeholder values
            like "change-me" are rejected. Keep it out of source control.
        algorithm: HMAC algorithm allowlist. Restricted to HS* so a future
            signer cannot be tricked into algorithm confusion (e.g. RS256
            public key passed as HMAC secret).
        access_token_expire_minutes: Short-lived access token lifetime.
        refresh_token_expire_days: Longer-lived refresh token lifetime.
    """

    model_config = ConfigDict(frozen=True)

    secret_key: str = Field(min_length=32, max_length=512)
    algorithm: JwtAlgorithm = "HS256"
    access_token_expire_minutes: int = Field(default=10, gt=0, le=30)
    refresh_token_expire_days: int = Field(default=7, gt=0, le=21)

    @field_validator("secret_key")
    @classmethod
    def _reject_placeholders(cls, v: str) -> str:
        """Refuse well-known placeholder/weak secrets at startup."""
        if v.strip().lower() in {"change-me", "changeme", "secret", "password", "test"}:
            raise ValueError("jwt secret_key must not be a placeholder value.")
        return v
