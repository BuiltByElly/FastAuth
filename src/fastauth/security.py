"""
(Do not import directly)
Password hashing helpers (argon2 via pwdlib by default).
"""

import secrets
from collections.abc import Callable

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.base import HasherProtocol
from pydantic import SecretStr


def _bcrypt_hasher() -> HasherProtocol:
    """Import bcrypt lazily: the backend is an optional extra."""
    from pwdlib.hashers.bcrypt import BcryptHasher

    return BcryptHasher()


SCHEME_HASHERS: dict[str, Callable[[], HasherProtocol]] = {
    "argon2": Argon2Hasher,
    "bcrypt": _bcrypt_hasher,
}
"""Scheme names devs may pick in `PasswordConfig.hash_schemes`."""

_default_hasher = PasswordHash.recommended()
"""Module-default hasher (argon2). Overridable per call via `hasher=`."""


def build_hasher(schemes: list[str] | None) -> PasswordHash:
    """Build a hasher from scheme names, or the default when None."""
    if schemes is None:
        return _default_hasher
    if not schemes:
        raise ValueError("hash_schemes must not be empty.")
    hashers = []
    for name in schemes:
        key = name.strip().lower()
        if key not in SCHEME_HASHERS:
            msg = f"Unknown password scheme {name!r}. Choose from {sorted(SCHEME_HASHERS)}."
            raise ValueError(msg)
        try:
            hashers.append(SCHEME_HASHERS[key]())
        except Exception as e:
            msg = f"Password scheme {key!r} is not installed ({e})."
            raise ValueError(msg) from e
    return PasswordHash(hashers)


def _reveal(password: str | SecretStr) -> str:
    """Unwrap a SecretStr to plaintext at the trust boundary.

    This is the ONLY place a secret is deliberately unwrapped: hashing and
    verification cannot run on the masked value. Callers keep holding
    SecretStr everywhere else so repr/str/JSON can never leak it.
    """
    if isinstance(password, SecretStr):
        return password.get_secret_value()
    return password


def hash_password(password: str | SecretStr, hasher: PasswordHash | None = None) -> str:
    """Hash a plaintext password (accepts SecretStr, unwraps it to hash)."""
    return (hasher or _default_hasher).hash(_reveal(password))


def verify_password(
    password: str | SecretStr, hashed: str, hasher: PasswordHash | None = None
) -> bool:
    """Check a plaintext password against its hash. Fail closed on bad hashes."""
    try:
        return (hasher or _default_hasher).verify(_reveal(password), hashed)
    except UnknownHashError:
        return False


DUMMY_PASSWORD_HASH: str = hash_password(
    "fastauth-dummy-password-for-timing-mitigation"
)
"""Pre-computed hash so login burns ~equal time on unknown emails.

Call ``verify_password(password, DUMMY_PASSWORD_HASH)`` before rejecting an
unknown user, narrowing the timing gap between "no such user" and
"wrong password" responses.
"""


class OAuthStateManager:
    """Issues and verifies the OIDC and OAuth2 `state` cookie.

    One instance per `OIDCAuth` or `OAuth2Auth`, keyed off the library's own secret —
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
