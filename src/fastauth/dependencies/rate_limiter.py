"""Rate limiting for FastAuth's own routes.

Devs configure (`FastAuthConfig(rate_limit=...)`) and, for
`storage="database"`, pass a `rate_limit_model` plus a
`rate_limiter_adapter`. `FastAuth` builds the limiter internally and
applies it to signup/login/refresh automatically.

Storage: `"memory"` shares one in-process limiter; `"database"` builds
the dev-picked ORM adapter per request. Disabled → no-ops, nothing raises.
"""

from collections.abc import AsyncGenerator, Awaitable, Callable
from typing import Annotated, Any

from fastapi import Depends, HTTPException, Request

from fastauth.adapters.adapters import RateLimiterAdapter
from fastauth.adapters.rate_limit.memory import InMemoryRateLimiter
from fastauth.config import RateLimitConfig
from fastauth.protocols import RateLimitProtocol

DependencyFn = Callable[..., Awaitable[None]]


class RateLimiter:
    """Fixed-window rate limiter (IP + path key) with pluggable storage.

    Built by `FastAuth` from config, or by hand and passed in — a passed
    instance always wins over `config.rate_limit`.
    """

    def __init__(
        self,
        rate_limiter_adapter: type[RateLimiterAdapter] | None = None,
        db_session_dependency: Callable[[], AsyncGenerator[Any]] | None = None,
        rate_limit_model: type[RateLimitProtocol] | None = None,
        rate_limit_config: RateLimitConfig | None = None,
    ):
        """Bind storage backend once; lives for the app lifetime.

        Args:
            rate_limiter_adapter: ORM adapter class (required for database storage).
            db_session_dependency: FastAPI dep yielding an AsyncSession (database only).
            rate_limit_model: App rate-limit model (database storage only).
            rate_limit_config: Limits, storage, per-route rules. Disabled → no-ops.
        """
        self._config = rate_limit_config or RateLimitConfig()
        self._dependency: Callable[..., Awaitable[RateLimiterAdapter]] | None = None

        if not self._config.enabled:
            return  # no storage needed; limit()/limit_for() will return no-ops

        if self._config.storage == "memory":
            limiter = InMemoryRateLimiter()

            async def _provide_memory() -> RateLimiterAdapter:
                return limiter

            self._dependency = _provide_memory

        elif self._config.storage == "database":
            if rate_limit_model is None:
                raise ValueError(
                    "storage='database' requires a rate_limit_model."
                )
            if db_session_dependency is None:
                raise ValueError("storage='database' requires a db_session_dependency.")
            if rate_limiter_adapter is None:
                raise ValueError("storage='database' requires a rate_limiter_adapter.")

            async def _provide_db(
                db_session: Annotated[Any, Depends(db_session_dependency)],
            ) -> RateLimiterAdapter:
                return rate_limiter_adapter(
                    db_session=db_session, model=rate_limit_model
                )

            self._dependency = _provide_db

        else:
            raise ValueError(f"Unknown rate limit storage: {self._config.storage!r}")

    def limit_for(self, path: str) -> DependencyFn:
        """Dependency for one route: `custom_rules[path]`, else globals.

        Args:
            path: Route path as in `custom_rules` (e.g. "/login").
        """
        window, max_requests = self._config.custom_rules.get(
            path, (self._config.window, self._config.max_requests)
        )
        return self.limit(window=window, max_requests=max_requests)

    def limit(
        self, window: int | None = None, max_requests: int | None = None
    ) -> DependencyFn:
        """Dependency enforcing an explicit limit (`None` → global config).

        Args:
            window: Time window in seconds. max_requests: Max hits per window.

        Usage:
            You can use this as a dependency in your FastAPI route if you want to implement
            FastAuth's rate limiting logic (Fixed-window rate limiting).

            rate_limiter = RateLimiter().limit(window, max_requests) -> DependencyFn
            @router.get("/", dependencies=[rate_limiter])
        """
        if not self._config.enabled or self._dependency is None:

            async def _noop(request: Request) -> None:
                return None

            return _noop

        win = self._config.window if window is None else window
        max_reqs = self._config.max_requests if max_requests is None else max_requests
        get_limiter = self._dependency
        trusted_header = (
            self._config.trusted_ip_header
        )  # None = use request.client.host only

        async def _dependency(
            request: Request,
            limiter: Annotated[RateLimiterAdapter, Depends(get_limiter)],
        ) -> None:
            ip = _client_ip(request, trusted_header)
            allowed = await limiter.check(f"{ip}:{request.url.path}", win, max_reqs)
            if not allowed:
                raise HTTPException(status_code=429, detail="Too many requests.")

        return _dependency


def _client_ip(request: Request, trusted_header: str | None) -> str:
    """Real client IP. Only trusts `trusted_header` if the dev opted in explicitly."""
    if trusted_header:
        value = request.headers.get(trusted_header)
        if value:
            return value.split(",")[0].strip()
    return request.client.host if request.client else "unknown"
