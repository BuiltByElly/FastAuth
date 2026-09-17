"""Password hashing helpers (argon2 via pwdlib)."""

from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError

_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Hash a plaintext password."""
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Check a plaintext password against its hash. Fail closed on bad hashes."""
    try:
        return _hasher.verify(password, hashed)
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
