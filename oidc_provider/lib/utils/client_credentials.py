from django.contrib.auth.hashers import check_password
from django.contrib.auth.hashers import make_password


def hash_secret(plaintext: str) -> str:
    """Hash a client secret using Django's configured password hasher (default: PBKDF2)."""
    return make_password(plaintext)


def verify_secret(plaintext: str, hashed: str) -> bool:
    """Verify a submitted secret against a stored hash using Django's constant-time check."""
    return check_password(plaintext, hashed)
