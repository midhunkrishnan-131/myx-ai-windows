"""
Automated Pytest Suite: test_auth_and_sessions.py
Covers Argon2id hashing, password strength policy, and SHA-256 session/reset token hashing.
"""
import pytest
from app.auth.password import (
    hash_password_argon2id,
    verify_password_argon2id,
    validate_password_strength,
    sha256_token_hash,
)


def test_argon2id_password_hash_and_verify():
    raw = "MyxDefense#2026!StrongPass"
    hashed = hash_password_argon2id(raw)
    assert hashed.startswith("$argon2id$")
    assert verify_password_argon2id(hashed, raw) is True
    assert verify_password_argon2id(hashed, "WrongPassword123!") is False


def test_rejects_short_or_breached_passwords():
    valid_short, _ = validate_password_strength("short123")
    assert valid_short is False

    valid_breached, _ = validate_password_strength("password123456")
    assert valid_breached is False


def test_session_token_sha256_hashing():
    token = "myx_sess_live_token_998877"
    digest = sha256_token_hash(token)
    assert len(digest) == 64
    assert digest != token
