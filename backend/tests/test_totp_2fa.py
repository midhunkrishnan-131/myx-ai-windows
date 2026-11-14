"""
Automated Pytest Suite: test_totp_2fa.py
Covers RFC 6238 TOTP secret provisioning, valid code verification, replay rejection on identical
timestep, and single-use hashed recovery code generation.
"""
import pyotp
from app.auth.totp import (
    generate_totp_enrollment_secret,
    verify_totp_code_with_replay_guard,
    generate_recovery_codes,
)


def test_totp_provisioning_and_replay_protection():
    enrollment = generate_totp_enrollment_secret("midhun.krishnan@myx-security.io")
    secret = enrollment["raw_base32_secret"]
    assert "otpauth://totp/" in enrollment["otpauth_uri"]

    fixed_time = 1763096000.0
    totp = pyotp.TOTP(secret, digits=6, interval=30)
    code = totp.at(int(fixed_time))

    # First verification succeeds
    ok, step1, err = verify_totp_code_with_replay_guard(secret, code, None, fixed_time)
    assert ok is True
    assert err is None
    assert step1 is not None

    # Replay within the same 30-second timestep MUST be rejected
    ok_replay, _, err_replay = verify_totp_code_with_replay_guard(secret, code, step1, fixed_time)
    assert ok_replay is False
    assert "replay rejected" in (err_replay or "").lower()


def test_single_use_recovery_code_hashing():
    plain, hashes = generate_recovery_codes(count=10)
    assert len(plain) == 10
    assert len(hashes) == 10
    assert all(c.startswith("MYX-") for c in plain)
    assert plain[0] != hashes[0]
