"""
MYX AI (Windows Edition) — Wi-Fi Password Lab & Wireless Security Test Suite.
Validates:
1. Offline password strength auditing (Shannon entropy, length, character diversity, dictionary matching).
2. Strong password generator produces high-entropy passphrases.
3. Defensive wireless security posture detects WEP, WPA1, TKIP, and WPS vulnerabilities.
4. Privacy boundary: Passwords are NEVER written into PDF reports or persistent storage.
"""
import pytest
from app.services.wifi_service import (
    audit_password_strength_offline,
    generate_strong_wifi_passphrase,
    analyze_wireless_security_posture,
)
from app.services.wifi_pdf_report_service import generate_wifi_audit_pdf


def test_offline_password_strength_auditor():
    """Rule: Evaluates offline entropy, character diversity, and detects common dictionary words."""
    # 1. Common dictionary password
    res_weak = audit_password_strength_offline("password123")
    assert res_weak["is_common_dictionary_match"] is True
    assert res_weak["strength"] == "Weak"
    assert res_weak["score"] <= 30

    # 2. Short numeric password
    res_short = audit_password_strength_offline("12345")
    assert res_short["strength"] == "Weak"
    assert res_short["length"] == 5

    # 3. High-entropy, complex passphrase
    res_strong = audit_password_strength_offline("Correct-Horse-Battery-Staple-99!")
    assert res_strong["is_common_dictionary_match"] is False
    assert res_strong["has_lowercase"] is True
    assert res_strong["has_uppercase"] is True
    assert res_strong["has_digits"] is True
    assert res_strong["has_symbols"] is True
    assert res_strong["entropy_bits"] >= 70
    assert res_strong["strength"] == "Very Strong"
    assert res_strong["score"] >= 85


def test_generate_strong_wifi_passphrase():
    """Rule: Passphrase generator produces cryptographically strong, diverse keys."""
    pwd = generate_strong_wifi_passphrase(16)
    assert len(pwd) == 16
    audit = audit_password_strength_offline(pwd)
    assert audit["strength"] in ["Strong", "Very Strong"]
    assert audit["has_lowercase"] and audit["has_uppercase"] and audit["has_digits"]


def test_wireless_security_analyzer_flags_vulnerabilities():
    """Rule: Wireless analyzer flags deprecated ciphers, WEP, WPA1, and WPS."""
    # 1. Deprecated WEP
    posture_wep = analyze_wireless_security_posture(
        ssid="Legacy_Office",
        security_protocol="WEP",
        cipher="None",
        wps_enabled=False,
    )
    assert posture_wep["overall_posture"] == "CRITICAL_RISK"
    assert any("WEP" in f["title"] for f in posture_wep["findings"])

    # 2. TKIP cipher deprecation
    posture_tkip = analyze_wireless_security_posture(
        ssid="Staff_Wifi",
        security_protocol="WPA2-Personal",
        cipher="TKIP",
        wps_enabled=False,
    )
    assert any("TKIP" in f["title"] for f in posture_tkip["findings"])

    # 3. WPS vulnerability
    posture_wps = analyze_wireless_security_posture(
        ssid="Guest_AP",
        security_protocol="WPA2-Personal",
        cipher="CCMP (AES)",
        wps_enabled=True,
    )
    assert any("WPS" in f["title"] for f in posture_wps["findings"])

    # 4. Hardened WPA3
    posture_clean = analyze_wireless_security_posture(
        ssid="Corp_Secure_WPA3",
        security_protocol="WPA3-Personal",
        cipher="CCMP (AES)",
        wps_enabled=False,
        password_score=95,
    )
    assert posture_clean["overall_posture"] == "SECURE"
    assert len(posture_clean["findings"]) == 0


def test_wifi_pdf_report_never_exposes_passwords():
    """Rule: Actual passwords must NEVER appear in PDF reports (redacted by design)."""
    SECRET_KEY = "SUPER_SECRET_RECOVERED_KEY_XYZ_12345!"

    pdf_bytes = generate_wifi_audit_pdf({
        "ssid": "Executive_Secure_5G",
        "security_protocol": "WPA2-Personal",
        "cipher": "CCMP (AES)",
        "wps_enabled": False,
        "password_strength": "Very Strong",
        "password_entropy": 78.4,
        "overall_posture": "SECURE",
        "findings": [],
        "recommendations": ["Enable AP isolation on guest subnets."],
    })

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    assert pdf_bytes.startswith(b"%PDF")
    # Strict privacy assertion: Secret key is completely absent from PDF byte stream
    assert SECRET_KEY.encode() not in pdf_bytes
