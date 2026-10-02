import secrets

import httpx2
from authlib.integrations.httpx_client import AsyncOAuth2Client
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from joserfc import jwt
from joserfc.jwk import KeySet
from joserfc.jwt import JWTClaimsRegistry

from fastauth.schemas import OIDCUserInfo


class OIDCStateManager:
    """Issues and verifies the OIDC `state` cookie.

    One instance per `OIDCAuth`, keyed off the library's own secret —
    not the dev's session secret, so it stays isolated from whatever
    else they store in cookies.
    """

    def __init__(self, secret_key: str, max_age: int = 300):
        self.serializer = URLSafeTimedSerializer(secret_key, salt="fastauth-oidc-state")
        self.max_age = max_age

    def generate(self, provider: str) -> tuple[str, str]:
        raw_state = secrets.token_urlsafe(32)
        payload = {"state": raw_state, "provider": provider}
        signed = self.serializer.dumps(payload)
        return raw_state, signed

    def verify(
        self, cookie_value: str | None, returned_state: str | None, provider: str
    ) -> bool:
        if not cookie_value or not returned_state:
            return False
        try:
            payload = self.serializer.loads(cookie_value, max_age=self.max_age)
        except BadSignature, SignatureExpired:
            return False
        if payload.get("provider") != provider:
            return False
        return secrets.compare_digest(payload["state"], returned_state)


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

    async def fetch_user_info(self, code: str, redirect_uri: str) -> OIDCUserInfo:
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

    def _normalize(self, claims: dict) -> OIDCUserInfo:
        known_keys = {"sub", "email", "email_verified", "name", "picture"}
        others = {k: v for k, v in claims.items() if k not in known_keys}

        return OIDCUserInfo(
            provider=self.name,
            provider_user_id=claims["sub"],
            email=claims.get("email"),
            email_verified=claims.get("email_verified", False),
            name=claims.get("name"),
            avatar_url=claims.get("picture"),
            others=others or None,
        )
