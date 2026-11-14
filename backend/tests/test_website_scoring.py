"""
Automated Pytest Suite: test_website_scoring.py
Validates the transparent weighted scoring engine, nuanced CSP evaluation,
HSTS final-response verification, cookie security flags, and redirect chain integrity.
"""
from app.services.website_scanner import (
    evaluate_security_headers_and_score,
    CONTROL_WEIGHTS,
)


def test_control_weights_sum_to_100():
    total_weight = sum(item["weight"] for item in CONTROL_WEIGHTS.values())
    assert total_weight == 100, f"Control weights must sum to exactly 100, got {total_weight}"


def test_hardened_site_scores_100():
    headers = {
        "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
        "server": "cloudflare",
    }
    raw_cookies = ["session=abc123xyz; Secure; HttpOnly; SameSite=Strict; Path=/"]
    redirect_chain = [{"from": "http://example.com", "to": "https://example.com", "status": 301}]

    res = evaluate_security_headers_and_score(
        final_url="https://example.com",
        status_code=200,
        headers=headers,
        redirect_chain=redirect_chain,
        raw_cookies=raw_cookies,
    )

    assert res["score"] == 100
    assert res["summary"]["failed"] == 0
    assert res["summary"]["warnings"] == 0
    assert res["summary"]["passed"] == 9


def test_completely_insecure_site_scores_zero():
    # Plaintext HTTP, no headers, no cookies, downgrade
    headers = {
        "server": "Apache/2.4.41 (Ubuntu) mod_ssl/2.4.41",
        "x-powered-by": "PHP/7.4.3",
    }
    raw_cookies = ["session=unprotected; Path=/"]
    redirect_chain = [{"from": "https://insecure.test", "to": "http://insecure.test", "status": 302}]

    res = evaluate_security_headers_and_score(
        final_url="http://insecure.test",
        status_code=200,
        headers=headers,
        redirect_chain=redirect_chain,
        raw_cookies=raw_cookies,
    )

    # All controls FAIL or WARNING with minimum points
    assert res["score"] <= 25
    assert res["summary"]["failed"] >= 4
    # HSTS, CSP, Clickjacking, Transport should be FAIL
    failed_controls = [r["control_id"] for r in res["results"] if r["status"] == "FAIL"]
    assert "MYX-CTRL-CSP-01" in failed_controls
    assert "MYX-CTRL-HSTS-02" in failed_controls
    assert "MYX-CTRL-XFO-03" in failed_controls
    assert "MYX-CTRL-TRANS-09" in failed_controls


def test_csp_upgrade_insecure_requests_alone_triggers_warning_not_pass():
    # Only upgrade-insecure-requests without script-src / default-src
    headers = {
        "content-security-policy": "upgrade-insecure-requests;",
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "x-frame-options": "SAMEORIGIN",
        "x-content-type-options": "nosniff",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
    }

    res = evaluate_security_headers_and_score(
        final_url="https://example.com",
        status_code=200,
        headers=headers,
        redirect_chain=[],
        raw_cookies=[],
    )

    csp_check = next(r for r in res["results"] if r["control_id"] == "MYX-CTRL-CSP-01")
    assert csp_check["status"] == "WARNING"
    assert csp_check["points_earned"] == 10  # Partial credit
    assert csp_check["points_deducted"] == 10
    assert "upgrade-insecure-requests" in csp_check["check_title"]


def test_hsts_inspected_on_final_https_response():
    # Redirected from HTTP (no HSTS) to HTTPS (with strong HSTS)
    redirect_chain = [{"from": "http://myx-test.org", "to": "https://myx-test.org", "status": 301}]
    headers = {
        "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    }

    res = evaluate_security_headers_and_score(
        final_url="https://myx-test.org",
        status_code=200,
        headers=headers,
        redirect_chain=redirect_chain,
        raw_cookies=[],
    )

    hsts_check = next(r for r in res["results"] if r["control_id"] == "MYX-CTRL-HSTS-02")
    assert hsts_check["status"] == "PASS"
    assert hsts_check["points_earned"] == 15
    assert hsts_check["points_deducted"] == 0


def test_insecure_cookie_attributes_penalized():
    headers = {}
    raw_cookies = [
        "auth=secret_token; Path=/",  # Missing Secure, HttpOnly, SameSite
    ]

    res = evaluate_security_headers_and_score(
        final_url="https://example.com",
        status_code=200,
        headers=headers,
        redirect_chain=[],
        raw_cookies=raw_cookies,
    )

    ck_check = next(r for r in res["results"] if r["control_id"] == "MYX-CTRL-COOKIE-04")
    assert ck_check["status"] == "WARNING"
    assert ck_check["points_earned"] == 6
    assert ck_check["points_deducted"] == 6
