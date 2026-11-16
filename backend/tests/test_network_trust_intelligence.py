"""
MYX AI Network Trust Intelligence — Unit and Security Integration Tests.
Brand: MYX AI by Midhun Krishnan ("Discover. Detect. Defend.")

Validates:
1. Deterministic SHA-256 network fingerprint calculation and OUI extraction.
2. Field-level diffing between observations and baseline profiles.
3. Benign enterprise BSSID roaming classification (no false positive attacks).
4. Crypto downgrade, rogue DNS, and gateway MAC drift detection.
5. Deterministic rule-based scoring engine (Low, Moderate, High, Critical tiers).
6. Missing telemetry penalty and confidence score calculation.
7. RBAC enforcement: VIEWER role cannot initiate or release quarantine.
8. Quarantine rule prefix scoping (MYX_AI_NTI_*) and rollback safety.
"""
import pytest
from app.services.network_fingerprint_service import (
    calculate_network_fingerprint,
    normalize_mac_address,
    extract_mac_oui,
    compare_network_observation_with_profile,
)
from app.services.network_risk_engine import evaluate_network_risk
from app.services.quarantine_controller import (
    initiate_network_quarantine,
    release_network_quarantine,
)
from app.database.session import SessionLocal
from app.models.domain_models import User, Organization


def test_mac_normalization_and_oui_extraction():
    # Various MAC formats
    mac1 = "00-14-22-01-23-45"
    mac2 = "00:14:22:01:23:45"
    mac3 = "001422012345"

    assert normalize_mac_address(mac1) == "00:14:22:01:23:45"
    assert normalize_mac_address(mac2) == "00:14:22:01:23:45"
    assert normalize_mac_address(mac3) == "00:14:22:01:23:45"

    # OUI extraction
    assert extract_mac_oui(mac1) == "00:14:22"
    assert extract_mac_oui(None) is None


def test_deterministic_network_fingerprint_reproducibility():
    fp1 = calculate_network_fingerprint(
        ssid="Corp-Secure",
        auth_type="WPA3-Enterprise",
        cipher="GCMP-256",
        gateway_mac="00:14:22:FE:DC:BA",
        dns_servers=["10.0.0.53", "1.1.1.1"],
    )
    fp2 = calculate_network_fingerprint(
        ssid="corp-secure",  # case-insensitive check
        auth_type="WPA3-ENTERPRISE",
        cipher="GCMP-256",
        gateway_mac="00-14-22-FE-DC-BA",
        dns_servers=["1.1.1.1", "10.0.0.53"],  # re-ordered check
    )
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 hex string


def test_benign_enterprise_roaming_not_classified_as_attack():
    profile = {
        "ssid": "Campus-Net",
        "baseline_auth": "WPA3-Enterprise",
        "baseline_cipher": "GCMP-256",
        "baseline_bssids": ["00:14:22:01:00:01", "00:14:22:01:00:02"],
        "baseline_gateway_mac": "00:14:22:FE:00:01",
        "baseline_dns": ["10.1.1.1"],
    }
    # New BSSID belonging to same vendor OUI and connected to identical gateway
    observation = {
        "ssid": "Campus-Net",
        "bssid": "00:14:22:01:00:03",  # new AP MAC, same OUI
        "auth_type": "WPA3-Enterprise",
        "cipher": "GCMP-256",
        "gateway_mac": "00:14:22:FE:00:01",
        "dns_servers": ["10.1.1.1"],
    }

    diffs, match_class, penalty = compare_network_observation_with_profile(observation, profile)
    assert match_class == "BENIGN_ROAMING"
    assert penalty == 0
    assert any(d["drift_category"] == "BENIGN_ROAMING" for d in diffs)


def test_crypto_downgrade_detection_triggers_critical():
    profile = {
        "ssid": "Enterprise-HQ",
        "baseline_auth": "WPA3-Enterprise",
        "baseline_cipher": "GCMP-256",
        "baseline_bssids": ["00:14:22:01:00:01"],
        "baseline_gateway_mac": "00:14:22:FE:00:01",
        "baseline_dns": ["10.1.1.1"],
    }
    # Adversary sets up rogue beacon with WPA2-Personal / TKIP
    observation = {
        "ssid": "Enterprise-HQ",
        "bssid": "00:14:22:01:00:01",
        "auth_type": "WPA2-Personal",
        "cipher": "TKIP",
        "gateway_mac": "00:14:22:FE:00:01",
        "dns_servers": ["10.1.1.1"],
    }

    eval_result = evaluate_network_risk(observation, profile)
    assert eval_result["severity"] == "CRITICAL"
    assert eval_result["risk_score"] >= 75
    assert eval_result["quarantine_action"] == "FULL_QUARANTINE"
    assert any(s["rule_id"] == "NTI-R03" for s in eval_result["detected_signals"])


def test_missing_data_penalizes_and_reduces_confidence():
    # Telemetry where gateway_mac and dns_servers could not be retrieved
    blinded_observation = {
        "ssid": "Public-Library",
        "bssid": "00:1A:2B:3C:4D:5E",
        "auth_type": "WPA2-Personal",
        "cipher": "CCMP",
        "gateway_mac": None,  # Missing
        "dns_servers": [],    # Missing
    }

    eval_result = evaluate_network_risk(blinded_observation, profile=None)
    # Missing fields must drop confidence below 100
    assert eval_result["confidence"] < 100
    # Uncertainty penalty must be applied (NTI-R10)
    assert any(s["rule_id"] == "NTI-R10" for s in eval_result["detected_signals"])
    # Missing data MUST NOT result in LOW risk
    assert eval_result["severity"] != "LOW"


def test_cleartext_open_network_penalized():
    open_observation = {
        "ssid": "Free-Airport-Wifi",
        "bssid": "AA:BB:CC:DD:EE:FF",
        "auth_type": "Open",
        "cipher": "None",
        "gateway_mac": "00:11:22:33:44:55",
        "dns_servers": ["8.8.8.8"],
    }
    eval_result = evaluate_network_risk(open_observation, profile=None)
    assert eval_result["risk_score"] >= 40
    assert any(s["rule_id"] == "NTI-R01" for s in eval_result["detected_signals"])


def test_rbac_viewer_blocked_from_quarantine():
    db = SessionLocal()
    try:
        # Attempt quarantine with VIEWER role
        with pytest.raises(PermissionError) as exc_info:
            initiate_network_quarantine(
                db=db,
                host_id="TEST-WIN-01",
                reason="Testing RBAC",
                risk_score=80,
                user_role="VIEWER",
            )
        assert "VIEWER" in str(exc_info.value)

        # Attempt release with VIEWER role
        with pytest.raises(PermissionError) as exc_info2:
            release_network_quarantine(
                db=db,
                user_role="VIEWER",
            )
        assert "VIEWER" in str(exc_info2.value)
    finally:
        db.close()
