"""
Genuine RFC 6238 TOTP Two-Factor Authentication (pyotp) with Replay Protection
and Single-Use Hashed Recovery Codes.
"""
import secrets
import time
import pyotp
from app.auth.password import sha256_token_hash


def generate_totp_enrollment_secret(user_email: str, issuer: str = "MYX AI") -> dict:
    base32_secret = pyotp.random_base32(length=32)  # 160-bit Base32 secret
    totp = pyotp.TOTP(base32_secret, digits=6, interval=30)
    provisioning_uri = totp.provisioning_uri(name=user_email, issuer_name=issuer)
    grouped = " ".join(base32_secret[i : i + 4] for i in range(0, len(base32_secret), 4))
    return {
        "raw_base32_secret": base32_secret,
        "manual_secret_grouped": grouped,
        "otpauth_uri": provisioning_uri,
    }


def verify_totp_code_with_replay_guard(
    base32_secret: str,
    candidate_code: str,
    last_verified_timestep: int | None,
    current_unix_time: float | None = None,
) -> tuple[bool, int | None, str | None]:
    """
    Verifies a 6-digit RFC 6238 TOTP code (valid_window=1 for +-30s clock drift)
    and rejects replay if timestep <= last_verified_timestep.
    """
    clean_code = candidate_code.strip()
    if len(clean_code) != 6 or not clean_code.isdigit():
        return False, last_verified_timestep, "Invalid 6-digit TOTP format."

    now = current_unix_time if current_unix_time is not None else time.time()
    totp = pyotp.TOTP(base32_secret, digits=6, interval=30)
    current_timestep = int(now // 30)

    matched_timestep: int | None = None
    for offset in (-1, 0, 1):
        ts = current_timestep + offset
        if totp.at(ts * 30) == clean_code:
            matched_timestep = ts
            break

    if matched_timestep is None:
        return False, last_verified_timestep, "Invalid or expired TOTP verification code."

    if last_verified_timestep is not None and matched_timestep <= last_verified_timestep:
        return (
            False,
            last_verified_timestep,
            "TOTP replay rejected: code for this 30-second time-step has already been used.",
        )

    return True, matched_timestep, None


def generate_recovery_codes(count: int = 10) -> tuple[list[str], list[str]]:
    """
    Returns (plaintext_codes_shown_once, sha256_hashes_stored_in_db).
    """
    plaintext_codes: list[str] = []
    hashed_codes: list[str] = []
    for _ in range(count):
        part_a = secrets.token_hex(2).upper()
        part_b = secrets.token_hex(2).upper()
        code = f"MYX-{part_a}-{part_b}"
        plaintext_codes.append(code)
        hashed_codes.append(sha256_token_hash(code))
    return plaintext_codes, hashed_codes
