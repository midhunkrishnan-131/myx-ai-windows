"""
Automated Pytest Suite: test_ssrf_and_target_guard.py
Covers loopback, localhost, RFC 1918 private IPs, and unconditional blocking of 169.254.169.254 cloud metadata.
"""
import pytest
from app.security.ssrf_guard import (
    SsrfBlockedError,
    validate_ip_address,
    validate_and_resolve_target_url,
)


def test_ssrf_blocks_loopback_and_localhost():
    with pytest.raises(SsrfBlockedError):
        validate_ip_address("127.0.0.1")

    with pytest.raises(SsrfBlockedError):
        validate_and_resolve_target_url("http://localhost:8000/api/v1/health")


def test_ssrf_unconditionally_blocks_cloud_metadata_in_all_modes():
    with pytest.raises(SsrfBlockedError):
        validate_ip_address("169.254.169.254", allow_controlled_lab=True, admin_lab_approved=True)


def test_ssrf_blocks_rfc1918_unless_lab_and_admin_approved():
    with pytest.raises(SsrfBlockedError):
        validate_ip_address("192.168.1.50", allow_controlled_lab=False, admin_lab_approved=False)

    allowed = validate_ip_address("192.168.1.50", allow_controlled_lab=True, admin_lab_approved=True)
    assert str(allowed) == "192.168.1.50"
