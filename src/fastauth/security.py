"""Password hashing helpers (argon2 via pwdlib)."""

from pwdlib import PasswordHash

_hasher = PasswordHash.recommended()


def hash_password(password: str) -> str:
    """Hash a plaintext password."""
    return _hasher.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Check a plaintext password against its hash."""
    return _hasher.verify(password, hashed)
