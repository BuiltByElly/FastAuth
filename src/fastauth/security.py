"""
(Do not import directly)
Password hashing helpers (argon2 via pwdlib by default).
"""

from collections.abc import Callable

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
