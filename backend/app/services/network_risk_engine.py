"""
MYX AI Network Trust Intelligence — Deterministic Network Risk Engine.
Brand: MYX AI by Midhun Krishnan ("Discover. Detect. Defend.")

Authoritative Principles:
- 100% deterministic rule-based evaluation (zero LLM in scoring loop).
- Separates Risk Score (0-100) from Confidence (0-100).
- Missing data is NEVER treated as proof of safety (uncertainty penalties applied).
- Four discrete severity tiers: LOW (0-24), MODERATE (25-49), HIGH (50-74), CRITICAL (75-100).
- Implements Balanced Protection Mode response recommendations.
"""
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone

from app.services.network_fingerprint_service import (
    compare_network_observation_with_profile,
    normalize_mac_address,
)


# Configurable default policy thresholds
DEFAULT_THRESHOLDS = {
    "LOW_MAX": 24,
    "MODERATE_MAX": 49,
    "HIGH_MAX": 74,
    "CRITICAL_MIN": 75,
}


def evaluate_network_risk(
    observation: Dict[str, Any],
    profile: Optional[Dict[str, Any]] = None,
    custom_policy: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Evaluates current WLAN & Layer 3 observation against known profile and security rules.
    Outputs structured risk evaluation ledger with explainable evidence.
    """
    diff_records, match_classification, diff_penalty = compare_network_observation_with_profile(
        observation, profile
    )

    detected_signals: List[Dict[str, Any]] = []
    rule_penalties: List[int] = []
    
    # Base Confidence Calculation (starts at 100, drops for missing fields)
    confidence = 100
    missing_fields: List[str] = []

    # 1. Telemetry Completeness Checks (NTI-R10)
    if not observation.get("gateway_mac") or observation.get("gateway_mac") == "UNAVAILABLE":
        missing_fields.append("gateway_mac")
        confidence -= 25

    if not observation.get("dns_servers") or len(observation.get("dns_servers")) == 0:
        missing_fields.append("dns_servers")
        confidence -= 20

    if not observation.get("ssid") or observation.get("ssid") in ("<hidden>", "UNAVAILABLE"):
        missing_fields.append("ssid")
        confidence -= 30

    if missing_fields:
        rule_penalties.append(15)
        detected_signals.append({
            "rule_id": "NTI-R10",
            "name": "Incomplete Telemetry / Adapter Blinded",
            "severity": "LOW",
            "penalty": 15,
            "evidence": {"missing_fields": missing_fields},
            "explanation": f"Telemetry observation is missing critical Layer 2/3 parameters: {', '.join(missing_fields)}. Uncertainty penalty applied.",
        })

    # 2. Cleartext Open Wireless Network (NTI-R01)
    auth_upper = (observation.get("auth_type") or "").upper()
    cipher_upper = (observation.get("cipher") or "").upper()
    if "OPEN" in auth_upper or "NONE" in cipher_upper:
        rule_penalties.append(40)
        detected_signals.append({
            "rule_id": "NTI-R01",
            "name": "Cleartext Open Wireless Network",
            "severity": "HIGH",
            "penalty": 40,
            "evidence": {"auth_type": auth_upper, "cipher": cipher_upper},
            "explanation": "Active Wi-Fi connection lacks 802.11 link-layer encryption or Opportunistic Wireless Encryption (OWE). All unencrypted traffic is subject to passive over-the-air interception.",
        })

    # 3. Deprecated Legacy Cipher Suite (NTI-R02)
    if "WEP" in cipher_upper or "TKIP" in cipher_upper or "WEP" in auth_upper:
        rule_penalties.append(50)
        detected_signals.append({
            "rule_id": "NTI-R02",
            "name": "Deprecated Cipher Suite (WEP/TKIP)",
            "severity": "HIGH",
            "penalty": 50,
            "evidence": {"cipher": cipher_upper},
            "explanation": "Connection is negotiating cryptographically compromised WEP or WPA-TKIP ciphers, vulnerable to practical keystream recovery and forgery attacks.",
        })

    # 4. Profile Differential Rules (NTI-R03, R04, R05, R06, R07, R08)
    for d in diff_records:
        cat = d.get("drift_category")
        if cat == "CRITICAL_DOWNGRADE":
            rule_penalties.append(65)
            detected_signals.append({
                "rule_id": "NTI-R03",
                "name": "Active Cryptographic Downgrade",
                "severity": "CRITICAL",
                "penalty": 65,
                "evidence": {"baseline": d.get("baseline"), "observed": d.get("observed")},
                "explanation": d.get("explanation"),
            })
        elif cat == "SUSPICIOUS_CHANGE" and d.get("field") == "gateway_mac":
            rule_penalties.append(45)
            detected_signals.append({
                "rule_id": "NTI-R04",
                "name": "Gateway MAC Drift / Potential ARP Spoofing",
                "severity": "HIGH",
                "penalty": 45,
                "evidence": {"baseline_gateway_mac": d.get("baseline"), "observed_gateway_mac": d.get("observed")},
                "explanation": d.get("explanation"),
            })
        elif cat == "SUSPICIOUS_CHANGE" and d.get("field") == "dns_servers":
            rule_penalties.append(35)
            detected_signals.append({
                "rule_id": "NTI-R05",
                "name": "Rogue DNS Server Injection",
                "severity": "MEDIUM",
                "penalty": 35,
                "evidence": {"baseline_dns": d.get("baseline"), "observed_dns": d.get("observed")},
                "explanation": d.get("explanation"),
            })
        elif cat == "SSID_MISMATCH":
            rule_penalties.append(70)
            detected_signals.append({
                "rule_id": "NTI-R06",
                "name": "Evil-Twin SSID Mismatch / Impersonation",
                "severity": "CRITICAL",
                "penalty": 70,
                "evidence": {"profile_ssid": d.get("baseline"), "observed_ssid": d.get("observed")},
                "explanation": d.get("explanation"),
            })
        elif cat == "UNKNOWN_NETWORK":
            rule_penalties.append(25)
            detected_signals.append({
                "rule_id": "NTI-R08",
                "name": "Unapproved Unknown Wi-Fi Network",
                "severity": "MEDIUM",
                "penalty": 25,
                "evidence": {"ssid": observation.get("ssid"), "bssid": observation.get("bssid")},
                "explanation": d.get("explanation"),
            })
        elif cat == "SUSPICIOUS_CHANGE" and d.get("field") == "captive_portal":
            rule_penalties.append(30)
            detected_signals.append({
                "rule_id": "NTI-R07",
                "name": "Captive Portal Interception",
                "severity": "MEDIUM",
                "penalty": 30,
                "evidence": {"captive_portal_detected": True},
                "explanation": d.get("explanation"),
            })
        elif cat == "NEW_ACCESS_POINT":
            rule_penalties.append(15)
            detected_signals.append({
                "rule_id": "NTI-R09",
                "name": "Unrecognized Access Point BSSID",
                "severity": "LOW",
                "penalty": 15,
                "evidence": {"new_bssid": d.get("observed"), "known_bssids": d.get("baseline")},
                "explanation": d.get("explanation"),
            })

    # Mathematical Score Formulation
    raw_score = sum(rule_penalties)
    risk_score = max(0, min(100, raw_score))
    final_confidence = max(10, min(100, confidence))

    # Determine Severity Tier
    thresholds = custom_policy.get("thresholds") if custom_policy else DEFAULT_THRESHOLDS
    low_max = thresholds.get("LOW_MAX", 24)
    mod_max = thresholds.get("MODERATE_MAX", 49)
    high_max = thresholds.get("HIGH_MAX", 74)

    if risk_score <= low_max:
        severity = "LOW"
        recommended_action = "Network characteristics verified against baseline. Continue passive background monitoring."
        quarantine_action = "NONE"
    elif risk_score <= mod_max:
        severity = "MODERATE"
        recommended_action = "Minor network drift or unknown profile. Notify user, recommend verifying network identity, and continue monitoring."
        quarantine_action = "NOTIFY_USER"
    elif risk_score <= high_max:
        severity = "HIGH"
        recommended_action = "High-confidence network threat detected. Recommend applying selective traffic restrictions to sensitive enterprise routes and notifying user."
        quarantine_action = "SELECTIVE_RESTRICTION"
    else:
        severity = "CRITICAL"
        recommended_action = "Severe wireless threat (crypto downgrade or evil-twin). Recommend immediate scoped quarantine of Wi-Fi adapter while preserving emergency recovery access."
        quarantine_action = "FULL_QUARANTINE"

    # Assemble Structured Explainable Evidence
    evidence_payload = {
        "host_id": observation.get("host_id", "LOCAL-WINDOWS-HOST"),
        "ssid": observation.get("ssid"),
        "bssid": normalize_mac_address(observation.get("bssid")),
        "auth_type": auth_upper,
        "cipher": cipher_upper,
        "signal_quality": observation.get("signal_quality"),
        "gateway_ip": observation.get("gateway_ip"),
        "gateway_mac": normalize_mac_address(observation.get("gateway_mac")),
        "dns_servers": observation.get("dns_servers", []),
        "missing_telemetry": missing_fields,
        "match_classification": match_classification,
    }

    # Summary Explanation
    if severity == "LOW":
        summary_explanation = f"Network '{observation.get('ssid')}' matches approved security baseline. No active downgrade, rogue AP, or ARP spoofing signals detected."
    else:
        top_reasons = [s["name"] for s in detected_signals[:2]]
        summary_explanation = f"Risk evaluated as {severity} ({risk_score}/100, confidence {final_confidence}%). Triggered by: {'; '.join(top_reasons)}."

    return {
        "risk_score": risk_score,
        "severity": severity,
        "confidence": final_confidence,
        "detected_signals": detected_signals,
        "field_diffs": diff_records,
        "evidence": evidence_payload,
        "explanation": summary_explanation,
        "recommended_action": recommended_action,
        "quarantine_action": quarantine_action,
        "policy_applied": custom_policy.get("name", "Balanced Protection Mode Default") if custom_policy else "Balanced Protection Mode Default",
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }
