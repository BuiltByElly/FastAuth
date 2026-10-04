# API reference

Manually maintained surface of the public modules. Anything not listed here is internal. Guide-level explanations live in [Strategies](../strategies/session.md) and [Guides](../guides/adapters.md); this page is signatures, types, and return values.

## Entry points (`fastauth`, `fastauth.core`)

### `SessionAuth`

```python
SessionAuth(
    adapter: type[Adapter],
    db_session_dependency: Callable[[], AsyncGenerator[Any]],
    user_model: type[UserT],
    session_model: type[SessionT],
    rate_limiter: RateLimiter | None = None,
    tags: list[str | Enum] | None = None,
    prefix: str = "/auth",
    config: FastAuthConfig | None = None,
    password_reset_token_model: type[PasswordResetTokenT] | None = None,
)
```

- Attributes: `.router: APIRouter`, `.current_user` (session-cookie dependency), `.config`, `.ctx: AuthContext`, `.password_hasher`, built schemas (`.signup_schema`, `.login_schema`, `.user_response_schema`, `.password_reset_token_schema`).
- Hook decorators: `.on_before_signup`, `.on_after_signup`, `.on_signup_failure`, `.on_before_login`, `.on_login_failure`, `.on_after_login`, `.on_after_logout`, `.on_token_reuse_detected` (no-op holder on sessions), `.on_password_reset_requested`, `.on_password_changed`.
- `strategy` is the class attribute `"session"`, not a constructor arg.

### `JWTAuth`

```python
JWTAuth(
    adapter: type[Adapter],
    db_session_dependency: Callable[[], AsyncGenerator[Any]],
    user_model: type[UserT],
    refresh_model: type[RefreshT],
    rate_limiter: RateLimiter | None = None,
    tags: list[str | Enum] | None = None,
    prefix: str = "/auth",
    config: FastAuthConfig | None = None,   # must include jwt=JWTConfig(...)
    password_reset_token_model: type[PasswordResetTokenT] | None = None,
)
```

Raises `ValueError` when `config.jwt` is missing. Same attributes/hooks as `SessionAuth`, plus `.refresh_model`, working `on_token_reuse_detected`, and:

- `await auth.purge_expired_refresh_tokens(session: Any) -> int` — deletes expired refresh rows via the adapter (flushes; caller commits). Designed for a scheduler job.

### `OIDCAuth`

```python
OIDCAuth(
    adapter: type[Adapter],
    db_session_dependency: Callable[[], AsyncGenerator[Any]],
    user_model: type[UserT],
    oauth_account_model: type[OAuthAccountT],
    strategy: Literal["session", "jwt"],
    session_model: type[SessionT] | None = None,   # required when strategy="session"
    refresh_model: type[RefreshT] | None = None,   # required when strategy="jwt"
    tags: list[str | Enum] | None = None,          # default: [provider names]
    prefix: str = "/auth/oidc",
    config: FastAuthConfig | None = None,          # must include oidc=OIDCConfig(...)
    rate_limiter: RateLimiter | None = None,
)
```

- Attributes: `.router`, `.current_user` (session or JWT flavor per `strategy`), `.config`, `.ctx: OIDCContext`, `.providers: dict[str, OIDCProvider]`, `.state_manager: OAuthStateManager`.
- Hooks: `.on_after_oidc_login(fn)` only — none of the password-flow hooks exist here.
- Raises `ValueError` for missing `config.oidc` / missing strategy model, `TypeError` for non-compliant models. Skips `FastAuth.__init__` deliberately (see [ARCHITECTURE](../../ARCHITECTURE.md)).

### `OAuth2Auth`

Same shape as `OIDCAuth` with `prefix="/auth/oauth2"`, `config.oauth2: OAuth2Config`, `.providers: dict[str, OAuth2Provider]`, `.ctx: OAuth2Context`, and `.on_after_oauth2_login(fn)`.

### `FastAuth`

Shared base: config, schemas, router, hook holders, per-request adapter binding. Registers no routes and sets no `current_user` — not usable directly; use the four classes above.

## Config (`fastauth.config`)

All models frozen (`ValidationError` on mutation). Generate secrets with `openssl rand -hex 32`.

- `FastAuthConfig(session=SessionConfig(), cookies=CookieConfig(), password=PasswordConfig(), rate_limit=RateLimitConfig(), oidc: OIDCConfig | None = None, oauth2: OAuth2Config | None = None, jwt: JWTConfig | None = None)`
- `SessionConfig(expire_days: int = 7)` — `gt=0, le=30`.
- `CookieConfig(session_cookie_name="fastauth_session", refresh_cookie_name="fastauth_refresh", secure: bool = True, samesite: SameSite = "lax", path="/", domain: str | None = None)` — names reject `; , space = "`; `samesite="none"` requires `secure=True`.
- `PasswordConfig(min_length=8, max_length=128, hash_schemes: list[str] | None = None)` — `min_length >= 1`, lengths consistent; `None` keeps argon2 `recommended()`, e.g. `["bcrypt"]` to switch. Lengths flow into signup/login/reset schemas.
- `JWTConfig(secret_key: str, algorithm: JWTAlgorithm = "HS256", access_token_expire_minutes=10, refresh_token_expire_days=7)` — secret 32–512 chars, placeholders rejected (`change-me`, `secret`, `password`, `test`, …); algorithm `HS256`/`HS384`/`HS512`; access `1–30` min, refresh `1–30` days.
- `RateLimitConfig(enabled=True, window=60, max_requests=100, storage: Literal["database","memory","redis"] = "memory", trusted_ip_header: str | None = None, custom_rules: dict[str, tuple[int,int]])` — defaults: `/login (10,3)`, `/signup (60,3)`, `/refresh (60,5)`, `/forgot-password (300,3)`, `/reset-password (300,3)`, `/{provider}/login (60,10)`, `/{provider}/callback (60,5)`.
- `OIDCConfig(secret_key: str, providers: list[OIDCProviderConfig] = [])` — frozen; same placeholder rejection as JWT.
- `OIDCProviderConfig(name, client_id, client_secret, redirect_uri, metadata_url: str, scopes=["openid","email","profile"], extra_authorize_params: dict[str,str] = {})`.
- `OAuth2Config(secret_key: str, providers: list[OAuth2ProviderConfig] = [])` — frozen, same secret rules.
- `OAuth2ProviderConfig(name, client_id, client_secret, redirect_uri, authorization_url, token_url, userinfo_url: str, scopes: list[str] = [], map_profile_to_user: Callable[[dict], Awaitable[OAuthUserInfo]], extra_authorize_params: dict[str,str] = {})`.

## Adapters

### `Adapter` ABC (`fastauth.adapters.adapters`)

Subclass for a custom ORM. Stores one request-scoped `db_session` plus app models; **flush, never commit** (routes commit; only the rate limiter commits inside `check()`).

```python
# classmethods
get_extra_fields(model: type) -> dict[str, tuple[type, Any]]      # fastauth_input columns
get_response_fields(model: type) -> dict[str, tuple[type, Any]]   # fastauth_returned columns
# users / credentials
get_user_by_email(email: str) -> UserT | None
get_user_by_id(user_id: Any) -> UserT | None
create_user(data: dict[str, Any]) -> UserT                        # hash data["password"]
issue_credential(user: UserT) -> SessionT | str                   # row (session) or token (JWT)
resolve_credential(token: str) -> UserT | None
revoke_credential(token: str) -> str | None                       # returns user id
# guards (raise ValueError when the model wasn't provided)
require_password_reset_model() -> type[PasswordResetTokenT]
require_oauth_account_model() -> type[OAuthAccountT]
# OAuth identities (EmailAlreadyRegistered on email collision)
get_oidc_account(provider: str, provider_user_id: str) -> OAuthAccountT | None
create_user_from_oidc(user_info: OAuthUserInfo) -> UserT
get_oauth2_account(provider: str, provider_user_id: str) -> OAuthAccountT | None
create_user_from_oauth2(user_info: OAuthUserInfo) -> UserT
# refresh tokens (base defaults raise NotImplementedError)
issue_refresh_token(user: UserT) -> str
consume_refresh_token(token: str) -> UserT | None                 # single-use burn
revoke_refresh_token(token: str) -> str | None
purge_expired_refresh_tokens() -> int
# password reset
create_password_reset_token(user: UserT) -> str                   # returns raw token, stores hash
consume_password_reset_token(token: str) -> UserT | None          # single-use, 15-min
set_password(user: UserT, new_password: str) -> None
revoke_credentials_on_password_reset(user: UserT) -> None
```

`RateLimiterAdapter` ABC: `check(key: str, window: int, max_requests: int) -> bool` — `True` if allowed (and counted).

### SQLAlchemy (`fastauth.adapters.sqlalchemy`)

- `SQLAlchemySessionAdapter(db_session: AsyncSession, user_model, session_model, jwt_config=None, refresh_model=None, session_expire_days=7, password_hasher=None, password_reset_token_model=None, oauth_account_model=None)` — `issue_credential` returns the session row; `resolve_credential` rejects unknown/expired/inactive; session logout `revoke_credential` deletes the row; password reset deletes the user's sessions.
- `SQLAlchemyJWTAdapter(...)` — same constructor (session_model unused); `issue_credential(user) -> str` (signed access token), `resolve_credential` validates type/`exp`/user, `revoke_credential` is a no-op returning the user id for the hook; refresh rotation is single-use with family revocation on reuse (`RefreshTokenReused` internally), `purge_expired_refresh_tokens() -> int`.
- Mixins (`models.py`) — inherit plus your own `__tablename__` (and `user_id` FK + unique constraints where noted):
  - `FastAuthUserMixin`: `id: UUID` (pk, `uuid7`), `email` (unique, indexed), `hashed_password: str | None`, `is_active: bool = True`, `password_changed_at: datetime`
  - `FastAuthSessionMixin`: `id: UUID` (pk, random `uuid4`), `expires_at`, `created_at` (+ your `user_id` FK)
  - `FastAuthRefreshTokenMixin`: `id: UUID` (pk, mirrors JWT `jti`), `expires_at`, `created_at`, `used_at: datetime | None`, `revoked_at: datetime | None` (+ your `user_id` FK)
  - `FastAuthRateLimitMixin`: `key: str` (pk), `count: int`, `window_start: datetime`
  - `FastAuthPasswordResetTokensMixin`: `id: UUID` (pk), `token_hash: str` (SHA-256 hex, unique), `expires_at`, `used_at: datetime | None` (+ your `user_id` FK)
  - `FastAuthOAuthAccountMixin`: `id: UUID` (pk), `provider: str`, `provider_user_id: str` (+ your `user_id` FK and mandatory unique `(provider, provider_user_id)`)

### Rate-limit backends (`fastauth.adapters.rate_limit`)

- `InMemoryRateLimiter()` — per-process dict; no constructor args.
- `SQLAlchemyRateLimiter(db_session: AsyncSession, model)` — `SELECT … FOR UPDATE` counter; commits even when denying (releases the lock); blocked hits don't inflate the count.
- `RedisRateLimiterAdapter(redis_client: redis.asyncio.Redis)` — one Lua script does atomic `INCR` + conditional `EXPIRE`; returns `bool(script_result)`.

### Exceptions (`fastauth.adapters.exceptions`)

- `EmailAlreadyRegistered(email: str | None)` — OAuth email collided with an existing account; routes map it to 400.
- `RefreshTokenReused(user_id: UUID)` — consumed refresh token presented again; the refresh route revokes the family and fires `on_token_reuse_detected`.

## Hooks (`fastauth.hooks`)

Handler aliases (all `async`, all observers return `None`):

```python
SignupHandler        = Callable[[BaseModel, Request], Awaitable[BaseModel]]   # before
SignupSuccessHandler = Callable[[BaseModel, Request], Awaitable[None]]
SignupFailureHandler = Callable[[str, Request], Awaitable[None]]               # error string
LoginHandler         = Callable[[BaseModel, Request], Awaitable[BaseModel]]   # before
LoginFailureHandler  = Callable[[LoginFailure, Request], Awaitable[None]]
LoginSuccessHandler  = Callable[[BaseModel, Request], Awaitable[None]]
LogoutHandler        = Callable[[str], Awaitable[None]]                       # user id
TokenReuseHandler    = Callable[[str, Request], Awaitable[None]]              # user id
PasswordResetHandler = Callable[[PasswordResetRequested, Request], Awaitable[None]]
PasswordChangedHandler = Callable[[PasswordChanged, Request], Awaitable[None]]
# oauth.py reuses the name LoginSuccessHandler for its own alias:
# OIDC observers receive OAuthUserInfo, OAuth2 observers receive OAuth2LoginResult
LoginSuccessHandler = Callable[[BaseModel, Request], Awaitable[None]]  # oauth.py
```

Holder methods (each `XxxHooks` class): `on_before_signup(fn)`, `on_after_signup(fn)`, `on_signup_failure(fn)`; `on_before_login(fn)`, `on_login_failure(fn)`, `on_after_login(fn)`; `LogoutHooks().add_after_logout(fn)` (exposed as `auth.on_after_logout`); `on_token_reuse_detected(fn)`; `on_password_reset_requested(fn)`, `on_password_changed(fn)`; `on_after_oidc_login(fn)`; `on_after_oauth2_login(fn)`. `run_*` counterparts execute them (before-runners re-validate and may raise; observer-runners never raise).

Events (`fastauth.hooks.models`, all frozen): `LoginFailure(user_id: str | None, error: str)`; `PasswordResetRequested(user_id: str, email: str, token: str)` — your handler sends the email; `PasswordChanged(user_id: str)`. Abort: `HookAbort(status_code=400, detail="Rejected")` (`fastauth.hooks`, an `HTTPException`).

## Providers & types (`fastauth.oauth`, `fastauth.types`)

```python
OIDCProvider(
    name: str, client_id: str, client_secret: str, metadata_url: str,
    scope: str = "openid email profile",
    extra_authorize_params: dict[str, str] | None = None,
)
await provider.get_authorize_url(redirect_uri: str, state: str) -> str
await provider.fetch_user_info(code: str, redirect_uri: str) -> OAuthUserInfo

OAuth2Provider(
    name: str, client_id: str, client_secret: str,
    authorization_url: str, token_url: str, userinfo_url: str,
    map_profile_to_user: Callable[[dict], Awaitable[OAuthUserInfo]],
    scope: str = "",
    extra_authorize_params: dict[str, str] | None = None,
)
await provider.get_authorize_url(redirect_uri: str, state: str) -> str
await provider.fetch_user_info(code: str, redirect_uri: str) -> OAuth2LoginResult
```

```python
OAuthUserInfo(provider: str, provider_user_id: str, email: str | None,
              email_verified: bool, name: str | None, avatar_url: str | None,
              others: dict[str, Any] | None = None)
OAuth2LoginResult(user_info: OAuthUserInfo, access_token: str,
                  refresh_token: str | None, expires_at: datetime | None)
```

## Schemas (`fastauth.schemas`)

Static: `LoginRequest(email: EmailStr, password: SecretStr)`; `UserResponseBase(id: UUID, email, is_active)`; `TokenResponse(access_token: str, token_type="access")`; `ForgotPasswordRequest(email)`; `ResetPasswordRequest(token: str, new_password: SecretStr)`. Builders (lengths honor `PasswordConfig`): `build_signup_schema(extra_fields, password_config?)`, `build_login_schema(password_config?)`, `build_user_response_schema(extra_fields)`, `build_password_reset_token_schema(password_config?)` — each returns a `type[BaseModel]`.

## Security & cookies (`fastauth.security`, `fastauth.cookies`)

- `hash_password(password: str | SecretStr, hasher: PasswordHash | None = None) -> str` — the only place a `SecretStr` is unwrapped.
- `verify_password(password: str | SecretStr, hashed: str, hasher: PasswordHash | None = None) -> bool` — fail-closed on unknown hashes.
- `OAuthStateManager(secret_key: str, max_age: int = 300)` — `generate(provider: str) -> tuple[raw_state, signed_cookie]` (43-char `token_urlsafe(32)` state), `verify(cookie_value: str | None, returned_state: str | None, provider: str) -> bool` (constant-time compare, provider-bound, expiry-checked).
- Cookies: `set_session_cookie(response, session_id, *, name?, max_age?, secure=True, samesite="lax", path="/", domain?)`, `set_refresh_cookie(...)` (same shape), `clear_session_cookie(response, *, ...)` / `clear_refresh_cookie(...)`, plus `session_cookie_kwargs(cfg, *, max_age)`, `refresh_cookie_kwargs(cfg, *, max_age)`, `clear_cookie_kwargs(cfg)`. Always `HttpOnly`; `SameSite=None` requires `secure=True`.

## Dependencies (`fastauth.dependencies`)

- `RateLimiter(rate_limiter_adapter?, db_session_dependency?, rate_limit_model?, rate_limit_config: RateLimitConfig | None = None, redis_client: redis.Redis | None = None)` — `memory` needs nothing; `database` raises `ValueError` without model/dependency/adapter; `redis` raises without client/adapter; `enabled=False` needs nothing and yields no-op dependencies. `.limit(window: int | None = None, max_requests: int | None = None)` and `.limit_for(path: str)` (looks up `custom_rules`, else globals) return FastAPI dependencies raising `429` on breach. Key is `ip:path`; `trusted_ip_header` opts into a client-controlled IP header.
- `current_user.py`: `session_current_user(ctx) -> dependency` (cookie → user, 401 otherwise), `jwt_current_user(ctx) -> dependency` (bearer → user, 401 + `WWW-Authenticate: Bearer`). Normally used as `Depends(auth.current_user)`.

## Protocols (`fastauth.protocols`)

Structural contracts (attribute names only) checked at startup by `ensure_model_compliance(model, protocol, *, name: str) -> None` (`TypeError` listing missing attributes): `UserProtocol(id, email, hashed_password, is_active)`, `SessionProtocol(id, user_id, expires_at, created_at)`, `RefreshTokenProtocol(+ used_at, revoked_at)`, `RateLimitProtocol(key, count, window_start)`, `PasswordResetTokenProtocol(id, user_id, token_hash, expires_at, used_at)`, `OAuthAccountProtocol(id, user_id, provider, provider_user_id)`. Generic `TypeVar`s (`UserT`, …) are intentionally unbound — SQLAlchemy `Mapped` invariance defeats static bounds.
