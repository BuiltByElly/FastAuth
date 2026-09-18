"""Auth configuration: one validated object, no I/O.

`FastAuthConfig` gathers every tunable in one place with secure defaults,
so `FastAuth(...)` works out of the box and a dev can override a single
nested section (e.g. `FastAuthConfig(session=SessionConfig(expire_days=3))`)
and hand it in via the `config` kwarg. All models are frozen + validated,
so bad values fail at startup instead of in production.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

SameSite = Literal["lax", "strict", "none"]
JWTAlgorithm = Literal["HS256", "HS384", "HS512"]


class RateLimitConfig(BaseModel):
    """Rate limiting for the FastAuth auth routes.

    Args:
        enabled: Master switch. Disabled → no storage, no limits, nothing raises.
        window: Global time window in seconds.
        max_requests: Global max hits per window.
        storage: "memory" (zero setup, single process) or "database"
            (multi-worker; requires rate_limit_model + rate_limiter_adapter).
        trusted_ip_header: Opt-in header for real client IP behind a proxy
            (e.g. "x-forwarded-for"). None = request.client.host only.
        custom_rules: Per-route (window, max) overrides, keyed by route path.
    """

    model_config = ConfigDict(frozen=True)

    enabled: bool = True
    window: int = Field(default=60, gt=0)  # seconds
    max_requests: int = Field(default=100, gt=0)
    # Memory by default so FastAuth works with zero setup (single process).
    # Switch to "database" + a rate_limit_model for multi-worker deployments.
    storage: Literal["database", "memory"] = "memory"
    trusted_ip_header: str | None = None

    # per-route overrides, Better Auth style — path -> (window, max)
    custom_rules: dict[str, tuple[int, int]] = Field(
        default_factory=lambda: {
            "/login": (10, 5),
            "/signup": (60, 3),
            "/refresh": (60, 10),
        }
    )


class JWTConfig(BaseModel):
    """Settings the JWT strategy signs and validates tokens with.

    Attributes:
        secret_key: HMAC secret. Minimum 32 chars; placeholder values
            like "change-me" are rejected. Keep it out of source control.
        algorithm: JWT algorithm to use for signing and validation.
        access_token_expire_minutes: Short-lived access token lifetime.
        refresh_token_expire_days: Longer-lived refresh token lifetime.
    """

    model_config = ConfigDict(frozen=True)

    secret_key: str = Field(min_length=32, max_length=512)
    algorithm: JWTAlgorithm = "HS256"
    access_token_expire_minutes: int = Field(default=10, gt=0, le=30)
    refresh_token_expire_days: int = Field(default=7, gt=0, le=30)

    @field_validator("secret_key")
    @classmethod
    def _reject_placeholders(cls, v: str) -> str:
        """Refuse well-known placeholder/weak secrets at startup."""
        if v.strip().lower() in {"change-me", "changeme", "secret", "password", "test"}:
            raise ValueError(
                "jwt secret_key must not be a placeholder value. Use `openssl rand -hex 32` to generate a secure key."
            )
        return v


class SessionConfig(BaseModel):
    """Session-strategy lifetimes."""

    model_config = ConfigDict(frozen=True)

    expire_days: int = Field(default=7, gt=0, le=30)


class CookieConfig(BaseModel):
    """Cookie transport for session ids (session) and refresh tokens (JWT).

    `httponly` is intentionally not a field: token cookies are always
    HttpOnly (no JS access). `secure` defaults True — Secure cookies work
    on http://localhost in modern browsers, so local dev is unaffected.
    """

    model_config = ConfigDict(frozen=True)

    session_cookie_name: str = Field(default="fastauth_session", min_length=1)
    refresh_cookie_name: str = Field(default="fastauth_refresh", min_length=1)
    secure: bool = True
    samesite: SameSite = "lax"
    path: str = "/"
    domain: str | None = None

    @field_validator("session_cookie_name", "refresh_cookie_name")
    @classmethod
    def _valid_cookie_name(cls, v: str) -> str:
        """Cookie names must survive a Set-Cookie header unquoted."""
        if any(c in v for c in (";", ",", " ", "=", '"')):
            raise ValueError("cookie name must not contain ';', ',', ' ', '=' or '\"'.")
        return v

    @model_validator(mode="after")
    def _samesite_needs_secure(self) -> CookieConfig:
        """Browsers drop SameSite=None cookies without Secure."""
        if self.samesite == "none" and not self.secure:
            raise ValueError("SameSite=None requires secure=True.")
        return self


class PasswordConfig(BaseModel):
    """Password policy (min 8 per NIST SP 800-63B) + hasher selection.\n
    Cap max_length at 72 when bcrypt is preferred over argon2 (default)."""

    model_config = ConfigDict(frozen=True)

    min_length: int = Field(default=8, ge=1, le=512)
    max_length: int = Field(default=128, ge=1, le=1024)
    hash_schemes: list[str] | None = None
    """pwdlib schemes (e.g. ["bcrypt"]); None keeps argon2 `recommended()`."""

    @model_validator(mode="after")
    def _lengths_consistent(self) -> PasswordConfig:
        """Min length must not exceed max length."""
        if self.min_length > self.max_length:
            raise ValueError("min_length must not exceed max_length.")
        return self


class FastAuthConfig(BaseModel):
    """Single config object for `FastAuth(..., config=...)`.

    Every section has secure defaults, so omitting `config` entirely
    behaves exactly like today's hardcoded values. Override per section:
    `FastAuthConfig(session=SessionConfig(expire_days=3))`.
    """

    model_config = ConfigDict(frozen=True)

    session: SessionConfig = SessionConfig()
    cookies: CookieConfig = CookieConfig()
    password: PasswordConfig = PasswordConfig()
    rate_limit: RateLimitConfig = RateLimitConfig()

    """Required iff strategy="jwt" (validated in `FastAuth.__init__`)."""
    jwt: JWTConfig | None = None
