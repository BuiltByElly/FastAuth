import httpx2
from authlib.integrations.httpx_client import AsyncOAuth2Client
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from fastauth.types import OAuthUserInfo


class OIDCProvider:
    def __init__(
        self,
        name: str,
        client_id: str,
        client_secret: str,
        metadata_url: str,
        scope: str = "openid email profile",
        extra_authorize_params: dict[str, str] | None = None,
    ):
        self.name = name
        self.client_id = client_id
        self.client_secret = client_secret
        self.metadata_url = metadata_url
        self.scope = scope
        self._metadata: dict | None = None
        self.extra_authorize_params = extra_authorize_params or {}

    async def _get_metadata(self) -> dict:
        if self._metadata is None:
            async with httpx2.AsyncClient() as client:
                resp = await client.get(self.metadata_url)
                resp.raise_for_status()
                self._metadata = resp.json()
        return self._metadata or {}

    async def get_authorize_url(self, redirect_uri: str, state: str) -> str:
        metadata = await self._get_metadata()
        client = AsyncOAuth2Client(self.client_id, scope=self.scope)
        uri, _ = client.create_authorization_url(
            metadata["authorization_endpoint"],
            redirect_uri=redirect_uri,
            state=state,
            **self.extra_authorize_params,
        )
        return uri

    async def fetch_user_info(self, code: str, redirect_uri: str) -> OAuthUserInfo:
        metadata = await self._get_metadata()
        client = AsyncOAuth2Client(
            self.client_id, self.client_secret, redirect_uri=redirect_uri
        )
        token = await client.fetch_token(metadata["token_endpoint"], code=code)

        async with httpx2.AsyncClient() as http_client:
            jwks_resp = await http_client.get(metadata["jwks_uri"])
            key_set = KeySet.import_key_set(jwks_resp.json())

        decoded = jwt.decode(token["id_token"], key_set)  # verifies signature only

        claims_registry = JWTClaimsRegistry(
            iss={"essential": True, "values": [metadata["issuer"]]},
            aud={"essential": True, "values": [self.client_id]},
            exp={"essential": True},
        )
        claims_registry.validate(
            decoded.claims
        )  # raises on missing/invalid exp, iss, aud

        return self._normalize(decoded.claims)

    def _normalize(self, claims: dict) -> OAuthUserInfo:
        known_keys = {"sub", "email", "email_verified", "name", "picture"}
        others = {k: v for k, v in claims.items() if k not in known_keys}

        return OAuthUserInfo(
            provider=self.name,
            provider_user_id=claims["sub"],
            email=claims.get("email"),
            email_verified=claims.get("email_verified", False),
            name=claims.get("name"),
            avatar_url=claims.get("picture"),
            others=others or None,
        )
