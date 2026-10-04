# Hooks

Two kinds, enforced in code:

| Kind | Register | Signature | Power |
|---|---|---|---|
| Before | `on_before_signup`, `on_before_login` | `(payload, request) -> payload` | mutate the payload, or block with `HookAbort(status_code, detail)` |
| Observer | everything else | `(event, request) -> None` | watch only; return value ignored |

- A crashing before-hook fails closed with a generic 500. A crashing observer is logged to `logging.getLogger("fastauth")` and ignored — observers run as background tasks after the response is sent, so they can never break or block it. Configure handlers yourself; the library only logs.
- Passwords reach **only** before-hooks, as `SecretStr`. Observers never see them.
- Failed logins always return the same generic error to the client; the reason (`LoginFailure.user_id`, `None` for unknown users) is for handlers only.

## Per class

`SessionAuth` / `JWTAuth`: `on_before_signup`, `on_after_signup`, `on_signup_failure`, `on_before_login`, `on_login_failure`, `on_after_login`, `on_after_logout(user_id)`, `on_password_reset_requested(PasswordResetRequested)`, `on_password_changed(PasswordChanged)` — plus `on_token_reuse_detected(user_id, request)` on JWT. Event shapes live in `fastauth.hooks.models`; abort with `fastauth.hooks.HookAbort`.

`OIDCAuth`: `on_after_oidc_login` receives the normalized `OAuthUserInfo`. `OAuth2Auth`: `on_after_oauth2_login` receives the `OAuth2LoginResult` (user info **plus the provider's own tokens** — persist or forward them in the hook; FastAuth doesn't).

`examples/basic/main.py` and `examples/jwt_example/main.py` show the password-flow hooks; `examples/oidc/main.py` and `examples/oauth2/main.py` show the OAuth ones. Handler type aliases and holder methods: [API reference](../reference/api.md#hooks-fastauthhooks).
