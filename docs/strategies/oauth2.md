# Plain OAuth2 login

GitHub-style login: providers that speak OAuth2 but not OIDC — no discovery document, no signed `id_token`. Full app: `examples/oauth2/main.py`, including the GitHub profile mapper quoted below.

```python
from fastauth.config import FastAuthConfig, OAuth2Config, OAuth2ProviderConfig
from fastauth.core import OAuth2Auth
from fastauth.types import OAuthUserInfo


async def map_github_profile(profile: dict) -> OAuthUserInfo:
    return OAuthUserInfo(
        provider="github",
        provider_user_id=str(profile["id"]),
        email=profile.get("email"),
        email_verified=True,
        name=profile.get("name") or profile.get("login"),
        avatar_url=profile.get("avatar_url"),
    )


oauth2 = OAuth2Auth(
    adapter=SQLAlchemySessionAdapter,
    user_model=User,
    session_model=Session,               # strategy="session" needs this
    db_session_dependency=get_db,
    oauth_account_model=OAuth2Account,   # FastAuthOAuthAccountMixin + unique (provider, provider_user_id)
    strategy="session",
    config=FastAuthConfig(
        oauth2=OAuth2Config(
            secret_key="<openssl rand -hex 32>",
            providers=[
                OAuth2ProviderConfig(
                    name="github",
                    client_id=...,
                    client_secret=...,
                    redirect_uri="http://localhost:8000/auth/oauth2/github/callback",
                    authorization_url="https://github.com/login/oauth/authorize",
                    token_url="https://github.com/login/oauth/access_token",
                    userinfo_url="https://api.github.com/user",
                    scopes=["read:user", "user:email"],
                    map_profile_to_user=map_github_profile,  # async; may call APIs
                )
            ],
        )
    ),
)
```

## How it works

Same shape as [OIDC](oidc.md): `GET /auth/oauth2/{provider}/login` → provider → `GET /auth/oauth2/{provider}/callback`. Differences:

- No discovery — `authorization_url`, `token_url`, `userinfo_url` are configured explicitly.
- No verified identity token — your async `map_profile_to_user` converts the raw profile JSON to `OAuthUserInfo` (it can make follow-up API calls, e.g. GitHub's separate emails endpoint).
- `on_after_oauth2_login` observers receive an `OAuth2LoginResult` carrying the provider's own access/refresh token. FastAuth **never persists** those tokens — the hook decides what to do with them.

Same fail-closed account rules as OIDC (no email takeover, inactive → 403, orphaned rows → 401). Full signatures: [`OAuth2Auth`](../reference/api.md#oauth2auth) and [`OAuth2Provider`](../reference/api.md#providers-types-fastauthoauth-fastauthtypes).
