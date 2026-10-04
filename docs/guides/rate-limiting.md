# Rate limiting

Fixed-window, keyed `ip:route-path`, applied as route dependencies. Configured in one place, or overridden per app with a ready-made `RateLimiter` (which then owns behavior and warns if `config.rate_limit` is non-default).

## Backends

| Storage | Needs | Scope |
|---|---|---|
| `"memory"` (default) | nothing | single process |
| `"database"` | `rate_limit_model` (a `FastAuthRateLimitMixin` table), `SQLAlchemyRateLimiter`, `db_session_dependency` | multi-worker; row-locked counter (`examples/jwt_example/main.py`) |
| `"redis"` | `RedisRateLimiterAdapter`, `redis_client` | multi-worker; Lua-atomic `INCR` + conditional `EXPIRE` (`examples/basic/main.py`) |

```python
# database (from examples/jwt_example/main.py)
rate_limiter = RateLimiter(
    rate_limit_model=RateLimitModel,
    rate_limiter_adapter=SQLAlchemyRateLimiter,
    db_session_dependency=get_db,
    rate_limit_config=RateLimitConfig(storage="database"),
)

# redis (from examples/basic/main.py)
rate_limiter = RateLimiter(
    rate_limiter_adapter=RedisRateLimiterAdapter,
    redis_client=redis_client,  # create per worker (e.g. in lifespan), not pre-fork
)
```

Pass it as `rate_limiter=` to any auth class. `RateLimiter(storage="database"|"redis")` without its requirements raises `ValueError` at startup. `RateLimitConfig(enabled=False)` disables everything — no storage needed.

## Rules

Defaults: 100 requests / 60s globally, tightened per route — `/login` (10, 3), `/signup` (60, 3), `/refresh` (60, 5), `/forgot-password` and `/reset-password` (300, 3), `/{provider}/login` (60, 10), `/{provider}/callback` (60, 5) — each tuple is `(window_seconds, max_requests)`. Override via `custom_rules`; fall back to the globals for unlisted paths. Rejected OAuth states still spend budget, so floods can't probe for free. Over-limit responses are 429 `"Too many requests"`. Set `trusted_ip_header` (e.g. `"x-forwarded-for"`) only when behind a proxy you trust — otherwise only `request.client.host` is used, so the header can't be spoofed. Constructor and dependency signatures: [`RateLimiter`](../reference/api.md#dependencies-fastauthdependencies).
