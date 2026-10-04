# Config reference

One frozen object: `FastAuthConfig(...)` passed as `config=` to any auth class. Bad values raise at startup. Generate secrets with `openssl rand -hex 32`. Every field with types and bounds: [API reference](../reference/api.md#config-fastauthconfig).

- **`session`** — `SessionConfig(expire_days=7)`, 1–30.
- **`cookies`** — `CookieConfig(session_cookie_name="fastauth_session", refresh_cookie_name="fastauth_refresh", secure=True, samesite="lax", path="/", domain=None)`. Token cookies are always `HttpOnly` (not configurable). `SameSite=None` requires `secure=True`.
- **`password`** — `PasswordConfig(min_length=8, max_length=128, hash_schemes=None)`. Argon2 (`recommended()`) by default; pass e.g. `["bcrypt"]` to switch (see `examples/basic/main.py`). Lengths apply to signup, login, and reset schemas.
- **`jwt`** — required for `JWTAuth` and `strategy="jwt"` OAuth. `JWTConfig(secret_key, algorithm="HS256", access_token_expire_minutes=10, refresh_token_expire_days=7)`. Secret 32–512 chars, placeholders (`change-me`, `secret`, `password`, `test`, …) rejected; algorithm one of `HS256`/`HS384`/`HS512`; access 1–30 min, refresh 1–30 days.
- **`rate_limit`** — `RateLimitConfig(enabled=True, window=60, max_requests=100, storage="memory", trusted_ip_header=None, custom_rules={…})`. See [Rate limiting](rate-limiting.md) for backends and the default rules.
- **`oidc`** — `OIDCConfig(secret_key, providers=[OIDCProviderConfig(name, client_id, client_secret, redirect_uri, metadata_url, scopes=["openid","email","profile"], extra_authorize_params={})])`. One `secret_key` signs every provider's state cookie, separate from `jwt.secret_key`.
- **`oauth2`** — `OAuth2Config(secret_key, providers=[OAuth2ProviderConfig(name, client_id, client_secret, redirect_uri, authorization_url, token_url, userinfo_url, scopes=[], map_profile_to_user, extra_authorize_params={})])`. `map_profile_to_user` is an async `(profile_dict) -> OAuthUserInfo` function — see `examples/oauth2/main.py`.

Model side: inherit the `fastauth.adapters.sqlalchemy.models` mixins (`FastAuthUserMixin`, `FastAuthSessionMixin`, `FastAuthRefreshTokenMixin`, `FastAuthRateLimitMixin`, `FastAuthPasswordResetTokensMixin`, `FastAuthOAuthAccountMixin`) and tag extra columns with `fastauth_input=True` (accepted on signup) / `fastauth_returned=True` (included in responses). Non-conforming models raise `TypeError` at startup naming the missing attributes.
