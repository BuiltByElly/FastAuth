# OIDC login

Google-style login: providers with a discovery document and a signed `id_token`. Full app: `examples/oidc/main.py`.

```python
from fastauth.config import FastAuthConfig, OIDCConfig, OIDCProviderConfig
from fastauth.core import OIDCAuth

oidc = OIDCAuth(
    adapter=SQLAlchemySessionAdapter,   # or SQLAlchemyJWTAdapter + refresh_model
    user_model=User,
    session_model=Session,               # strategy="session" needs this
    db_session_dependency=get_db,
    oauth_account_model=OIDCAccount,    # FastAuthOAuthAccountMixin + unique (provider, provider_user_id)
    strategy="session",                  # or "jwt" (then pass refresh_model + jwt config)
    config=FastAuthConfig(
        oidc=OIDCConfig(
            secret_key="<openssl rand -hex 32>",  # signs the state cookie, separate from jwt.secret_key
            providers=[
                OIDCProviderConfig(
                    name="google",
                    client_id=...,
                    client_secret=...,
                    redirect_uri="http://localhost:8000/auth/oidc/google/callback",
                    metadata_url="https://accounts.google.com/.well-known/openid-configuration",
                    scopes=["openid", "email", "profile"],  # the default
                    extra_authorize_params={"access_type": "offline", "prompt": "select_account"},
                )
            ],
        )
    ),
)
app.include_router(oidc.router)
```

## How it works

1. `GET /auth/oidc/{provider}/login` mints a random `state`, stores it in a signed, `HttpOnly`, 5-minute cookie, and redirects to the provider.
2. `GET /auth/oidc/{provider}/callback?code=…&state=…` verifies the cookie `state` (missing/mismatched/forged/expired/replayed → 400, provider-bound), exchanges the code, verifies the `id_token` signature (JWKS) plus `iss`/`aud`/`exp` claims, and normalizes the claims to `OAuthUserInfo`.
3. FastAuth links `(provider, sub)` to a user — creating a passwordless user + account row on first login — then issues credentials through the same adapter as password login (`strategy` picks session vs JWT).
4. `on_after_oidc_login` observers receive the `OAuthUserInfo`.

Fail-closed cases: an IdP email matching an existing password account → 400 (no takeover); a deactivated user → 403; an account row whose user is gone → 401.

`auth.current_user` works on OIDC instances too — use it to protect routes either way. Full signatures: [`OIDCAuth`](../reference/api.md#oidcauth) and [`OIDCProvider`](../reference/api.md#providers-types-fastauthoauth-fastauthtypes).
