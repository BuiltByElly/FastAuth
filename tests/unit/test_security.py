"""Unit tests: hashing, verification, and hasher selection."""

import pytest

from fastauth.security import (
    DUMMY_PASSWORD_HASH,
    build_hasher,
    hash_password,
    verify_password,
)


def test_hash_verify_roundtrip():
    hashed = hash_password("correct-horse")
    assert verify_password("correct-horse", hashed) is True
    assert verify_password("wrong-horse-1", hashed) is False


def test_verify_fails_closed_on_garbage_hash():
    assert verify_password("anything", "not-a-hash") is False
    assert verify_password("anything", "") is False


def test_build_hasher_defaults_to_module_default():
    assert build_hasher(None) is not None
    hashed = hash_password("pw", build_hasher(None))
    assert verify_password("pw", hashed) is True


def test_build_hasher_explicit_argon2():
    hasher = build_hasher(["argon2"])
    hashed = hash_password("pw", hasher)
    assert verify_password("pw", hashed, hasher) is True


def test_build_hasher_rejects_empty_and_unknown_schemes():
    with pytest.raises(ValueError, match="must not be empty"):
        build_hasher([])
    with pytest.raises(ValueError, match="Unknown password scheme"):
        build_hasher(["rot13"])


def test_bcrypt_scheme_end_to_end():
    bcrypt = pytest.importorskip("pwdlib.hashers.bcrypt")
    assert bcrypt is not None
    hasher = build_hasher(["bcrypt"])
    hashed = hash_password("bcrypt-password", hasher)
    assert verify_password("bcrypt-password", hashed, hasher) is True
    assert verify_password("wrong", hashed, hasher) is False


def test_dummy_hash_mitigates_enumeration_timing():
    assert isinstance(DUMMY_PASSWORD_HASH, str)
    assert DUMMY_PASSWORD_HASH
    # Usable as a burn-time comparison target; never authenticates.
    assert verify_password("fastauth-dummy-password-for-timing-mitigation",
                           DUMMY_PASSWORD_HASH) is True
    assert verify_password("attacker-guess", DUMMY_PASSWORD_HASH) is False
