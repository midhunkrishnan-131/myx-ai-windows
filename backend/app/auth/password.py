"""
Argon2id Password Hashing & Strength Enforcement (argon2-cffi).
Minimum parameters: memory_cost=65536 (64 MB), time_cost=3, parallelism=4.
"""
import hashlib
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

ph = PasswordHasher(memory_cost=65536, time_cost=3, parallelism=4, hash_len=32, salt_len=16)

COMMON_BREACHED_PASSWORDS = {
    "password123456",
    "admin12345678",
    "welcome123456",
    "qwertyuiop123",
    "myxai12345678",
}


def validate_password_strength(password: str) -> tuple[bool, str | None]:
    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    if password.lower() in COMMON_BREACHED_PASSWORDS:
        return False, "Password appears in known breached credential lists."
    return True, None


def hash_password_argon2id(password: str) -> str:
    valid, reason = validate_password_strength(password)
    if not valid:
        raise ValueError(reason)
    return ph.hash(password)


def verify_password_argon2id(password_hash: str, candidate_password: str) -> bool:
    try:
        return ph.verify(password_hash, candidate_password)
    except VerifyMismatchError:
        return False


def sha256_token_hash(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
