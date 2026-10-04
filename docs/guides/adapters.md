# Custom adapters

The DB layer is the `Adapter` ABC (`src/fastauth/adapters/adapters.py`). SQLAlchemy ships included (`SQLAlchemySessionAdapter`, `SQLAlchemyJWTAdapter`); any other ORM is a subclass away. Model compatibility is structural — see [Config](config.md) for the mixins, `src/fastauth/protocols.py` for the contracts.

Implement every abstract method (refresh-token methods default to `NotImplementedError`, so JWT-only adapters can skip the session side and vice versa — check which your strategy calls):

- `get_extra_fields(model)` / `get_response_fields(model)` — classmethods reading the `fastauth_input` / `fastauth_returned` column flags for dynamic schemas
- `get_user_by_email`, `get_user_by_id`
- `create_user(data)` — hash `data["password"]` into `hashed_password`
- `issue_credential(user)` / `resolve_credential(token)` / `revoke_credential(token)`
- `require_password_reset_model()` / `require_oauth_account_model()` — raise `ValueError` when unset
- `get_oidc_account` / `create_user_from_oidc`, `get_oauth2_account` / `create_user_from_oauth2`
- `issue_refresh_token` / `consume_refresh_token` (single-use burn) / `revoke_refresh_token` / `purge_expired_refresh_tokens`
- `create_password_reset_token` / `consume_password_reset_token` (single-use, 15-minute) / `set_password` / `revoke_credentials_on_password_reset`

Rules: **flush, never commit** — the route commits user + account (+ refresh) rows atomically with the credential. The only exception is the rate-limiter adapter, whose `check()` commits immediately because it runs as a route dependency. Raise `EmailAlreadyRegistered` (from `fastauth.adapters.exceptions`) when an OAuth email collides with an existing user so routes return 400 instead of taking the account over.

`ensure_model_compliance(model, Protocol, name=...)` from `src/fastauth/protocols.py` fails fast at startup when a model is missing attributes — call it in your constructor like the built-ins do. Every method signature and mixin column: [API reference](../reference/api.md#adapters).
