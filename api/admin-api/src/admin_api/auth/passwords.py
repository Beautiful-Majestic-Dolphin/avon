"""Password hashing with Argon2."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_ph = PasswordHasher()


def hash_password(password: str) -> str:
    """Hash a password with Argon2id."""
    return _ph.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against an Argon2 hash. Constant-time."""
    try:
        return _ph.verify(hashed, password)
    except VerifyMismatchError:
        return False
    except Exception:
        return False


def needs_rehash(hashed: str) -> bool:
    """Check if a hash needs rehashing (e.g., after parameter change)."""
    try:
        return _ph.check_needs_rehash(hashed)
    except Exception:
        return True
