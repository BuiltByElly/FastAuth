# ARCHITECTURE

How FastAuth's pieces fit together. Paths are under `src/fastauth/`.

```
src/fastauth/
├── __init__.py            # public surface: FastAuth, SessionAuth, JWTAuth, OIDCAuth, OAuth2Auth
├── core.py                # auth classes: shared base + four strategy entrypoints
├── config.py              # FastAuthConfig + nested section models (all frozen)
├── protocols.py           # ORM-neutral model contracts + runtime compliance check
├── schemas.py             # request/response models + dynamic schema builders
├── types.py               # shared dataclasses (exists to break an import cycle)
├── security.py            # password hashing, OAuthStateManager (state CSRF)
├── cookies.py             # cookie set/clear helpers (always HttpOnly)
├── adapters/
│   ├── adapters.py        # Adapter + RateLimiterAdapter ABCs
│   ├── exceptions.py      # domain errors (e.g. EmailAlreadyRegistered)
│   ├── sqlalchemy/        # SQLAlchemy backend: session + JWT adapters, model mixins
│   └── rate_limit/        # memory.py / sqlalchemy.py / redis.py limiter backends
├── routes/
│   ├── session.py         # SessionAuth endpoints (signup/login/logout/me/reset)
│   ├── jwt_route.py       # JWTAuth endpoints (+ refresh)
│   ├── oidc_route.py      # OIDC login/callback
│   ├── oauth2_route.py    # plain-OAuth2 login/callback
│   └── context.py         # AuthContext / OIDCContext / OAuth2Context (per-instance state)
├── oauth/                 # provider clients (not hooks, not routes)
│   ├── oidc.py            # OIDCProvider: discovery doc + id_token verification
│   └── oauth2.py          # OAuth2Provider: explicit URLs + dev-supplied profile mapper
├── dependencies/
│   ├── current_user.py    # session_current_user / jwt_current_user builders
│   └── rate_limiter.py    # RateLimiter: storage wiring + limit()/limit_for()
└── hooks/
    ├── signup.py login.py logout.py refresh.py password.py  # per-flow hook holders
    ├── oauth.py           # OIDCLoginHooks / OAuth2LoginHooks (after-login observers)
    ├── models.py          # LoginFailure, PasswordResetRequested, PasswordChanged
    └── exceptions.py      # HookAbort (how before-hooks block)
```

## Modules

- **`core.py`** — One class per strategy. `FastAuth` is the shared base (config, schemas, router, hook registration, per-request adapter binding); `SessionAuth`/`JWTAuth` extend it. `OIDCAuth`/`OAuth2Auth` subclass it for the type surface but skip its `__init__` (see below). Depends on: adapters, config, dependencies, hooks, oauth, routes, schemas, security.
- **`config.py`** — `FastAuthConfig` plus nested sections (`SessionConfig`, `CookieConfig`, `PasswordConfig`, `JWTConfig`, `RateLimitConfig`, `OIDCConfig`/`OIDCProviderConfig`, `OAuth2Config`/`OAuth2ProviderConfig`). Frozen models; placeholder secrets rejected; lifetimes bounded. Depends on: `types.py` (for `OAuthUserInfo` in the provider mapper signature).
- **`adapters/adapters.py`** — `Adapter` ABC (user/session/credential/password-reset/OAuth-account methods; flush, never commit) and `RateLimiterAdapter` ABC (`check(key, window, max)`). Depends on: config (`JWTConfig`), protocols, types.
- **`adapters/sqlalchemy/`** — `session_adapter.py` (`SQLAlchemySessionAdapter`), `jwt_adapter.py` (`SQLAlchemyJWTAdapter`), `mixins.py` (OAuth-account + password-reset shared logic), `models.py` (column mixins devs inherit: user, session, refresh, rate-limit, reset-token, OAuth-account). Depends on: base ABCs, protocols.
- **`adapters/rate_limit/`** — `memory.py` (single-process dict), `sqlalchemy.py` (`SELECT … FOR UPDATE` row-locked counter, commits even on the blocked path to release the lock), `redis.py` (Lua-atomic `INCR` + conditional `EXPIRE`). Depends on: base `RateLimiterAdapter` only.
- **`routes/`** — Endpoint registrars taking `(router, ctx)`. `session.py` / `jwt_route.py` serve signup, login, logout, forgot/reset-password, me (JWT adds refresh). `oidc_route.py` / `oauth2_route.py` serve `GET /{provider}/login` (mint `state`, set signed cookie, redirect) and `GET /{provider}/callback` (verify `state`, resolve user, issue credentials, fire after-login hook as a background task). `context.py` holds the per-instance state each registrar needs; `build_adapter(session)` binds the adapter class to the request's DB session. Depends on: adapters, config, cookies, dependencies (rate limiter), oauth providers, schemas.
- **`oauth/`** — Provider HTTP clients. `OIDCProvider` fetches the discovery doc, then verifies the `id_token` signature (JWKS) plus `iss`/`aud`/`exp` claims and normalizes to `OAuthUserInfo`. `OAuth2Provider` exchanges the code at the configured `token_url`, GETs the `userinfo_url`, and delegates identity mapping to the dev's `map_profile_to_user`, returning `OAuth2LoginResult` (user info + provider tokens). Depends on: `types.py` only.
- **`security.py`** — `hash_password`/`verify_password` (argon2 via pwdlib; `SecretStr` unwrapped only here) and `OAuthStateManager` (signed, timestamped, provider-bound `state` tokens shared by both OAuth strategies). Depends on: nothing in-library.
- **`hooks/`** — One holder class per flow. Before-hooks take `(payload, request)`, return the payload, and block with `HookAbort`; a crashing before-hook fails closed with 500. Observers (`on_after_*`, `on_*_failure`, `on_token_reuse_detected`, …) take their event, return nothing, run as background tasks after the response, and never raise (crashes are logged to `logging.getLogger("fastauth")`). Passwords reach only before-hooks, as `SecretStr`. Depends on: hook models/exceptions, FastAPI `Request`.
- **`schemas.py`** — Static bases (`LoginRequest`, `UserResponseBase`, …) plus builders that merge dev columns tagged `fastauth_input` / `fastauth_returned` at startup, honoring `PasswordConfig` lengths. Depends on: config.
- **`types.py`** — `OAuthUserInfo` and `OAuth2LoginResult` dataclasses. Depends on: stdlib only.
- **`protocols.py`** — Structural contracts (`UserProtocol`, `SessionProtocol`, …) plus `ensure_model_compliance`, which checks attribute names at startup and raises `TypeError` listing what's missing. Depends on: stdlib only.
- **`cookies.py`** — `set_*` / `clear_*` helpers and kwarg builders. Token cookies are always `HttpOnly`; `Secure` defaults to `True`. Depends on: config.
- **`dependencies/current_user.py`** — Builders returning the `auth.current_user` dependency: session-cookie lookup vs. bearer-token lookup, 401 with `WWW-Authenticate` on the JWT path. Depends on: route contexts.
- **`dependencies/rate_limiter.py`** — `RateLimiter` binds one storage backend at construction (`memory` needs nothing; `database` needs model + adapter + session dep; `redis` needs adapter + client) and exposes `limit()` / `limit_for(path)` route dependencies keyed `ip:path`. `trusted_ip_header` is opt-in; without it only `request.client.host` is used. Depends on: adapters, config, protocols.

## Design decisions

- **Why `OIDCAuth`/`OAuth2Auth` skip `FastAuth.__init__`.** The base builds password machinery — hasher, signup/login schemas, signup/login/password hooks — none of which applies to OAuth flows. The OAuth classes rebuild only the shared pieces (config, rate limiter, state manager, router, adapter binding) by hand, so password code can never run on an OAuth path.
- **Why OIDC and plain OAuth2 are separate providers.** OIDC has a discovery document and a signed `id_token` to verify; plain OAuth2 (GitHub-style) has neither — no discovery, no signed identity. So `OIDCProvider` hardcodes verification + normalization, while `OAuth2Provider` takes explicit URLs and a dev-supplied async mapper. The hook payloads differ accordingly: OIDC observers receive `OAuthUserInfo`; OAuth2 observers receive `OAuth2LoginResult`, which also carries the provider's own tokens. FastAuth never persists those tokens.
- **Why adapters flush and routes commit.** The adapter only stages rows; the route commits after issuing credentials, so user + account (+ refresh) rows land atomically with the credential. Exception: the rate limiter commits immediately — it runs as a route dependency, so a later endpoint failure (e.g. 401) must not roll back the attempt count.
- **Why `types.py` exists.** `config.py` needs `OAuthUserInfo` for the provider-mapper signature and `schemas.py` needs config for password lengths — importing either direction directly would cycle. `types.py` holds the shared dataclasses with stdlib-only imports so both can depend on it.
- **Why protocols are structural with unbound TypeVars.** SQLAlchemy `Mapped[...]` attributes are invariant, so no static bound can prove conformance — it would reject every valid model. Models just need the right attribute names (`ensure_model_compliance` at startup); behavior is enforced by the adapter test suite.
