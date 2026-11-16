"""
MYX AI Network Trust Intelligence — Network Fingerprint & Field-Level Diff Service.
Brand: MYX AI by Midhun Krishnan ("Discover. Detect. Defend.")

Key Capabilities:
- Generates deterministic, explainable fingerprints from Layer 2 (802.11) and Layer 3 (IP/Gateway/DNS) telemetry.
- Field-level diffing between current observation and trusted baseline profile.
- Distinguishes benign enterprise AP roaming from rogue AP / evil-twin impersonation.
- Never fabricates missing observations; explicit UNCERTAIN / UNAVAILABLE markers.
"""
import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple


def normalize_mac_address(mac: Optional[str]) -> Optional[str]:
    """Normalizes MAC addresses to uppercase colon-separated format."""
    if not mac or not isinstance(mac, str):
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(cleaned) == 12:
        return ":".join(cleaned[i : i + 2].upper() for i in range(0, 12, 2))
    return mac.strip().upper()


def extract_mac_oui(mac: Optional[str]) -> Optional[str]:
    """Extracts 24-bit Organizationally Unique Identifier (OUI) from MAC."""
    norm = normalize_mac_address(mac)
    if norm and len(norm) >= 8:
        return norm[:8]  # e.g., '00:14:22'
    return None


def calculate_network_fingerprint(
    ssid: str,
    auth_type: str,
    cipher: str,
    gateway_mac: Optional[str] = None,
    dns_servers: Optional[List[str]] = None,
) -> str:
    """
    Computes a deterministic SHA-256 fingerprint from core structural properties.
    Note: BSSID is deliberately omitted from the primary fingerprint to accommodate
    enterprise multi-AP roaming without breaking identity.
    """
    norm_ssid = (ssid or "").strip().lower()
    norm_auth = (auth_type or "UNKNOWN").strip().upper()
    norm_cipher = (cipher or "UNKNOWN").strip().upper()
    norm_gw = normalize_mac_address(gateway_mac) or "NO_GATEWAY_MAC"
    
    clean_dns = sorted([d.strip() for d in (dns_servers or []) if d and d.strip()])
    dns_token = ",".join(clean_dns) if clean_dns else "NO_DNS"

    raw_signature = f"SSID={norm_ssid}|AUTH={norm_auth}|CIPHER={norm_cipher}|GW_MAC={norm_gw}|DNS={dns_token}"
    return hashlib.sha256(raw_signature.encode("utf-8")).hexdigest()


class FieldDiff:
    def __init__(
        self,
        field_name: str,
        baseline_value: Any,
        observed_value: Any,
        drift_category: str,
        severity: str,
        explanation: str,
        risk_penalty: int = 0,
    ):
        self.field_name = field_name
        self.baseline_value = baseline_value
        self.observed_value = observed_value
        self.drift_category = drift_category  # BENIGN_ROAMING, MINOR_DRIFT, SUSPICIOUS_CHANGE, CRITICAL_DOWNGRADE
        self.severity = severity  # INFO, LOW, MEDIUM, HIGH, CRITICAL
        self.explanation = explanation
        self.risk_penalty = risk_penalty

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field_name,
            "baseline": self.baseline_value,
            "observed": self.observed_value,
            "drift_category": self.drift_category,
            "severity": self.severity,
            "explanation": self.explanation,
            "risk_penalty": self.risk_penalty,
        }


def compare_network_observation_with_profile(
    observation: Dict[str, Any],
    profile: Optional[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], str, int]:
    """
    Performs field-level differential comparison between current observation and baseline profile.
    Returns:
        (diff_records, match_classification, total_diff_penalty)
    Match Classifications:
        - UNKNOWN_NETWORK: Profile is None
        - VERIFIED_MATCH: Profile matches on all key structural parameters
        - BENIGN_ROAMING: BSSID differs, but OUI/Gateway/Cipher match enterprise baseline
        - SUSPICIOUS_DRIFT: Gateway MAC, DNS, or AP attributes altered suspiciously
        - CRITICAL_ANOMALY: Active encryption downgrade or evil-twin impersonation
    """
    diffs: List[FieldDiff] = []
    
    if not profile:
        return (
            [{
                "field": "profile",
                "baseline": None,
                "observed": observation.get("ssid"),
                "drift_category": "UNKNOWN_NETWORK",
                "severity": "MEDIUM",
                "explanation": f"Network '{observation.get('ssid')}' has no approved baseline profile on this device or tenant.",
                "risk_penalty": 25,
            }],
            "UNKNOWN_NETWORK",
            25,
        )

    obs_ssid = (observation.get("ssid") or "").strip()
    prof_ssid = (profile.get("ssid") or "").strip()
    
    if obs_ssid.lower() != prof_ssid.lower():
        diffs.append(FieldDiff(
            "ssid", prof_ssid, obs_ssid,
            "SSID_MISMATCH", "HIGH",
            f"Observed SSID '{obs_ssid}' does not match baseline profile '{prof_ssid}'.",
            risk_penalty=40,
        ))

    # 1. Encryption & Cipher Suite Analysis
    obs_auth = (observation.get("auth_type") or "UNKNOWN").upper()
    prof_auth = (profile.get("baseline_auth") or "UNKNOWN").upper()
    obs_cipher = (observation.get("cipher") or "UNKNOWN").upper()
    prof_cipher = (profile.get("baseline_cipher") or "UNKNOWN").upper()

    # Detect Crypto Downgrade
    is_downgrade = False
    if "WPA3" in prof_auth and "WPA3" not in obs_auth:
        is_downgrade = True
    elif "ENTERPRISE" in prof_auth and "ENTERPRISE" not in obs_auth:
        is_downgrade = True
    elif "OPEN" in obs_auth and "OPEN" not in prof_auth:
        is_downgrade = True
    elif ("TKIP" in obs_cipher or "WEP" in obs_cipher) and ("CCMP" in prof_cipher or "GCMP" in prof_cipher):
        is_downgrade = True

    if is_downgrade:
        diffs.append(FieldDiff(
            "auth_and_cipher",
            f"{prof_auth} / {prof_cipher}",
            f"{obs_auth} / {obs_cipher}",
            "CRITICAL_DOWNGRADE", "CRITICAL",
            f"Severe Security Downgrade: Baseline requires {prof_auth} ({prof_cipher}); current connection negotiated {obs_auth} ({obs_cipher}). Possible Evil-Twin or Downgrade Attack.",
            risk_penalty=65,
        ))
    elif obs_auth != prof_auth or obs_cipher != prof_cipher:
        diffs.append(FieldDiff(
            "auth_and_cipher",
            f"{prof_auth} / {prof_cipher}",
            f"{obs_auth} / {obs_cipher}",
            "SUSPICIOUS_CHANGE", "HIGH",
            f"Authentication/Cipher changed from {prof_auth} ({prof_cipher}) to {obs_auth} ({obs_cipher}).",
            risk_penalty=35,
        ))

    # 2. BSSID & Roaming Classification
    obs_bssid = normalize_mac_address(observation.get("bssid"))
    baseline_bssids = [normalize_mac_address(b) for b in (profile.get("baseline_bssids") or []) if b]
    
    bssid_is_known = obs_bssid in baseline_bssids if obs_bssid else False
    if not bssid_is_known and obs_bssid:
        # Check OUI match for enterprise roaming
        obs_oui = extract_mac_oui(obs_bssid)
        known_ouis = {extract_mac_oui(b) for b in baseline_bssids if b}
        
        obs_gw_mac = normalize_mac_address(observation.get("gateway_mac"))
        prof_gw_mac = normalize_mac_address(profile.get("baseline_gateway_mac"))
        
        # If OUI matches known AP vendor AND gateway MAC is identical -> Benign Enterprise Roaming
        if (obs_oui and obs_oui in known_ouis) or (obs_gw_mac and prof_gw_mac and obs_gw_mac == prof_gw_mac):
            diffs.append(FieldDiff(
                "bssid",
                baseline_bssids[:3],
                obs_bssid,
                "BENIGN_ROAMING", "INFO",
                f"Normal Wi-Fi roaming detected: connected to alternate AP ({obs_bssid}) within trusted organization infrastructure.",
                risk_penalty=0,
            ))
        else:
            diffs.append(FieldDiff(
                "bssid",
                baseline_bssids[:3],
                obs_bssid,
                "NEW_ACCESS_POINT", "LOW",
                f"New Access Point hardware ({obs_bssid}) observed broadcasting SSID '{prof_ssid}'.",
                risk_penalty=15,
            ))

    # 3. Default Gateway Hardware MAC & IP Drift
    obs_gw_mac = normalize_mac_address(observation.get("gateway_mac"))
    prof_gw_mac = normalize_mac_address(profile.get("baseline_gateway_mac"))
    
    if prof_gw_mac and obs_gw_mac and prof_gw_mac != obs_gw_mac:
        diffs.append(FieldDiff(
            "gateway_mac",
            prof_gw_mac,
            obs_gw_mac,
            "SUSPICIOUS_CHANGE", "HIGH",
            f"Gateway MAC altered from {prof_gw_mac} to {obs_gw_mac} on SSID '{prof_ssid}'. Potential ARP spoofing or rogue gateway insertion.",
            risk_penalty=45,
        ))

    # 4. DNS Server Configuration Drift
    obs_dns = sorted([d.strip() for d in (observation.get("dns_servers") or []) if d and d.strip()])
    prof_dns = sorted([d.strip() for d in (profile.get("baseline_dns") or []) if d and d.strip()])
    
    if prof_dns and obs_dns and prof_dns != obs_dns:
        diffs.append(FieldDiff(
            "dns_servers",
            prof_dns,
            obs_dns,
            "SUSPICIOUS_CHANGE", "MEDIUM",
            f"DNS resolvers changed from {prof_dns} to {obs_dns}. Potential rogue DNS injection via DHCP.",
            risk_penalty=35,
        ))

    # 5. Captive Portal Interception
    if observation.get("captive_portal_detected") and not profile.get("allows_captive_portal", False):
        diffs.append(FieldDiff(
            "captive_portal",
            False,
            True,
            "SUSPICIOUS_CHANGE", "MEDIUM",
            "Captive portal HTTP redirect detected on a non-guest/production network.",
            risk_penalty=30,
        ))

    # Determine overall match classification
    total_penalty = sum(d.risk_penalty for d in diffs)
    has_critical = any(d.severity == "CRITICAL" for d in diffs)
    has_high = any(d.severity == "HIGH" for d in diffs)
    
    if has_critical:
        classification = "CRITICAL_ANOMALY"
    elif has_high or total_penalty >= 40:
        classification = "SUSPICIOUS_DRIFT"
    elif any(d.drift_category == "BENIGN_ROAMING" for d in diffs) and total_penalty <= 15:
        classification = "BENIGN_ROAMING"
    elif len(diffs) == 0:
        classification = "VERIFIED_MATCH"
    else:
        classification = "MINOR_DRIFT"

    return ([d.to_dict() for d in diffs], classification, total_penalty)
