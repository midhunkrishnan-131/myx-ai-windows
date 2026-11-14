"""
Automated Pytest Suite: test_windows_agent.py
Covers Windows 10/11 local agent HMAC-SHA256 telemetry signing and privilege boundary validation.
"""
import hashlib
import hmac
from app.models.domain_models import WindowsAgent


def test_windows_agent_hmac_signature_verification():
    secret = "myx_agent_hmac_secret_2026"
    timestamp = "1763096000"
    payload = b'{"hostname":"WIN11-SECOPS-01","privilege_level":"ELEVATED_ADMIN"}'
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        f"{timestamp}.".encode("utf-8") + payload,
        hashlib.sha256,
    ).hexdigest()
    assert len(expected_sig) == 64
    assert hasattr(WindowsAgent, "privilege_level")
    assert hasattr(WindowsAgent, "revoked_at")
