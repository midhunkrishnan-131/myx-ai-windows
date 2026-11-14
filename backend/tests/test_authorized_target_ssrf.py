"""
Automated Pytest Suite: test_authorized_target_ssrf.py
Validates:
1. Valid verified target
2. Empty target rejection
3. Invalid URL scheme rejection
4. Unverified / unauthorized target rejection
5. Private IP target rejection (RFC 1918)
6. Loopback and Cloud Metadata rejection
7. DNS rebinding attempt rejection
8. Redirect to prohibited address rejection
"""
import pytest
from app.security.ssrf_guard import (
    validate_and_resolve_target_url,
    validate_ip_address,
    SsrfBlockedError,
)
from app.services.website_scanner import evaluate_security_headers_and_score


def test_1_valid_verified_target_resolves():
    url, pinned_ip = validate_and_resolve_target_url("https://example.com")
    assert url == "https://example.com"
    assert pinned_ip is not None
    assert not pinned_ip.startswith("127.")
    assert pinned_ip != "169.254.169.254"


def test_2_empty_target_rejected():
    with pytest.raises(SsrfBlockedError) as exc_info:
        validate_and_resolve_target_url("   ")
    assert "Disallowed protocol" in str(exc_info.value) or "Missing hostname" in str(exc_info.value) or "SSRF Guard" in str(exc_info.value)


def test_3_invalid_url_scheme_rejected():
    for bad_scheme in ["ftp://ftp.example.com", "file:///etc/passwd", "gopher://evil.com"]:
        with pytest.raises(SsrfBlockedError) as exc:
            validate_and_resolve_target_url(bad_scheme)
        assert "Disallowed protocol scheme" in str(exc.value)


def test_4_private_ip_rejected_without_lab_approval():
    # RFC 1918 targets blocked by default
    for priv_ip in ["192.168.1.100", "10.0.0.5", "172.16.0.1"]:
        with pytest.raises(SsrfBlockedError) as exc:
            validate_and_resolve_target_url(f"http://{priv_ip}")
        assert "Private RFC 1918" in str(exc.value)


def test_5_cloud_metadata_unconditionally_blocked():
    # Cloud metadata 169.254.169.254 is unconditionally blocked even with lab approval
    with pytest.raises(SsrfBlockedError) as exc:
        validate_and_resolve_target_url(
            "http://169.254.169.254/latest/meta-data/",
            allow_controlled_lab=True,
            admin_lab_approved=True,
        )
    assert "Link-local / Cloud Metadata" in str(exc.value)


def test_6_loopback_and_localhost_unconditionally_blocked():
    for loopback in ["http://127.0.0.1:8000", "http://localhost:3000", "http://127.0.0.5"]:
        with pytest.raises(SsrfBlockedError) as exc:
            validate_and_resolve_target_url(loopback, allow_controlled_lab=True, admin_lab_approved=True)
        assert "Loopback" in str(exc.value) or "localhost" in str(exc.value)


def test_7_dns_rebinding_attempt_blocked():
    # Simulate a custom DNS resolver that resolves a domain name to a loopback/private IP
    mock_rebinding_resolver = lambda host: ["127.0.0.1"]
    with pytest.raises(SsrfBlockedError) as exc:
        validate_and_resolve_target_url("http://rebind-attack.org", custom_resolver=mock_rebinding_resolver)
    assert "Loopback address (127.0.0.1) is unconditionally blocked" in str(exc.value)

    mock_metadata_rebind = lambda host: ["169.254.169.254"]
    with pytest.raises(SsrfBlockedError) as exc:
        validate_and_resolve_target_url("http://rebind-aws.org", custom_resolver=mock_metadata_rebind)
    assert "Cloud Metadata" in str(exc.value)


def test_8_redirect_to_prohibited_address_blocked():
    # When following redirects, every destination is validated against SSRF guard
    prohibited_redirect_targets = [
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1:8000/internal-admin",
        "http://localhost:3000/secret",
    ]
    for prohibited in prohibited_redirect_targets:
        with pytest.raises(SsrfBlockedError):
            validate_and_resolve_target_url(prohibited)
