# Session strategy

Cookie transport, server-side rows. `SessionAuth` with `SQLAlchemySessionAdapter`, a user model, and a session model. Full app: `examples/basic/main.py`.

```python
auth = SessionAuth(
    adapter=SQLAlchemySessionAdapter,
    user_model=User,
    session_model=Session,
    db_session_dependency=get_db,
    config=FastAuthConfig(session=SessionConfig(expire_days=7)),
)
```

## Behavior

- Login creates a session row and sets an `HttpOnly` cookie (`fastauth_session` by default; `secure=True` by default, `SameSite=lax`). Existing sessions rotate on login.
- `auth.current_user` resolves the user from the cookie; missing/expired/inactive → 401.
- Logout deletes the row and clears the cookie; replaying it stays 401.
- Password reset revokes the user's other sessions.

## Endpoints (prefix `/auth` by default)

`POST /signup`, `POST /login`, `POST /logout`, `POST /forgot-password`, `POST /reset-password`, `GET /me`.

## Config

`SessionConfig(expire_days=7)` (1–30 days) and `CookieConfig` (cookie names, `secure`, `samesite`, `path`, `domain`). See [Config](../guides/config.md). Full signatures: [`SessionAuth`](../reference/api.md#sessionauth).
