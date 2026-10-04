# JWT strategy

Stateless access tokens plus rotating refresh cookies. `JWTAuth` with `SQLAlchemyJWTAdapter` and a refresh-token model. Full app: `examples/jwt_example/main.py`.

```python
auth = JWTAuth(
    adapter=SQLAlchemyJWTAdapter,
    user_model=User,
    refresh_model=RefreshToken,
    db_session_dependency=get_db,
    config=FastAuthConfig(
        jwt=JWTConfig(secret_key="<openssl rand -hex 32>"),
    ),
)
```

## Behavior

- Login/signup return `{access_token, token_type}` (10-minute bearer token by default) and set the refresh cookie.
- `POST /refresh` consumes the refresh token **single-use** and returns a fresh pair. Reuse of an already-consumed token revokes the family and fires `on_token_reuse_detected`.
- `auth.current_user` reads the `Authorization: Bearer` header; missing/invalid → 401 with `WWW-Authenticate: Bearer`.
- `auth.purge_expired_refresh_tokens(session)` deletes expired rows; call it from a scheduler (caller commits).

## Endpoints (prefix `/auth` by default)

`POST /signup`, `POST /login`, `POST /refresh`, `POST /logout`, `POST /forgot-password`, `POST /reset-password`, `GET /me`.

## Config

`JWTConfig(secret_key, algorithm="HS256", access_token_expire_minutes=10, refresh_token_expire_days=7)`. Secrets need 32+ chars; placeholders (`change-me`, `secret`, …) are rejected. Access lifetime maxes at 30 minutes, refresh at 30 days. See [Config](../guides/config.md). Full signatures: [`JWTAuth`](../reference/api.md#jwtauth).
