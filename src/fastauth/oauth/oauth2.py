"""Generic plain-OAuth2 provider — one class, config-driven, same
pattern as OIDCProvider. No discovery doc exists for these providers,
so authorization_url/token_url/userinfo_url are supplied directly in
config, and identity mapping is the dev's own map_profile_to_user
function instead of a hardcoded _normalize().
"""

from collections.abc import Awaitable, Callable

import httpx2
from authlib.integrations.httpx_client import AsyncOAuth2Client

from fastauth.types import OAuth2LoginResult, OAuthUserInfo


class OAuth2Provider:
    def __init__(
        self,
        name: str,
        client_id: str,
        client_secret: str,
        authorization_url: str,
        token_url: str,
        userinfo_url: str,
        map_profile_to_user: Callable[[dict], Awaitable[OAuthUserInfo]],
        scope: str = "",
        extra_authorize_params: dict[str, str] | None = None,
    ):
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.authorization_url = authorization_url
        self.token_url = token_url
        self.userinfo_url = userinfo_url
        self.map_profile_to_user = map_profile_to_user
        self.scope = scope
        self.extra_authorize_params = extra_authorize_params or {}

    async def get_authorize_url(self, redirect_uri: str, state: str) -> str:
        client = AsyncOAuth2Client(self.client_id, scope=self.scope)
        uri, _ = client.create_authorization_url(
            self.authorization_url,
            redirect_uri=redirect_uri,
            state=state,
            **self.extra_authorize_params,
        )
        return uri

    async def fetch_user_info(self, code: str, redirect_uri: str) -> OAuth2LoginResult:
        client = AsyncOAuth2Client(
            self.client_id, self.client_secret, redirect_uri=redirect_uri
        )
        token = await client.fetch_token(self.token_url, code=code)

        async with httpx2.AsyncClient() as http_client:
            resp = await http_client.get(
                self.userinfo_url,
                headers={"Authorization": f"Bearer {token['access_token']}"},
            )
            resp.raise_for_status()
            profile = resp.json()

        user_info = await self.map_profile_to_user(profile)

        return OAuth2LoginResult(
            user_info=user_info,
            access_token=token["access_token"],
            refresh_token=token.get("refresh_token"),
            expires_at=token.get(
                "expires_at"
            ),  # Unix timestamp int, or None if provider omitted expires_in
        )
