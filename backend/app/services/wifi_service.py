"""
MYX AI (Windows Edition) — Authorized Wi-Fi Profile Discovery, Local Recovery & Offline Password Auditor.
Strict Privacy & Security Boundaries:
1. Operates strictly locally via Windows 'netsh wlan' commands.
2. Zero external transmission: recovered credentials are NEVER sent to Gemini, external APIs, or RAG.
3. Zero persistence: credentials are NEVER logged to disk, database, or conversation logs.
4. Offline password strength auditing: entropy calculation, dictionary checks, character diversity.
5. Defensive wireless security posture: detects open networks, deprecated WEP/WPA/TKIP, and WPS exposure.
"""
import subprocess
import re
import math
import secrets
import string
from typing import List, Dict, Any, Optional

# Top common passwords list for offline dictionary matching
COMMON_WEAK_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "admin", "welcome",
    "password123", "wifi1234", "internet", "guest123", "letmein", "11111111",
    "00000000", "pass1234", "router123", "office2024", "company123", "starbucks",
    "mywifi123", "wifipassword", "default", "administrator", "login123"
}


def discover_saved_wifi_profiles() -> List[Dict[str, Any]]:
    """
    Discovers previously saved Wi-Fi profiles on the user's authenticated Windows computer
    using 'netsh wlan show profiles'.
    """
    profiles: List[Dict[str, Any]] = []
    try:
        res = subprocess.run(
            ["netsh", "wlan", "show", "profiles"],
            capture_output=True,
            text=True,
            check=False,
            timeout=8
        )
        if res.returncode != 0:
            return profiles

        # Parse profile names: e.g., 'All User Profile     : SSID_NAME'
        lines = res.stdout.splitlines()
        for line in lines:
            if ":" in line and ("All User Profile" in line or "User Profile" in line):
                parts = line.split(":", 1)
                if len(parts) == 2:
                    ssid = parts[1].strip()
                    if ssid:
                        profiles.append({
                            "ssid": ssid,
                            "profile_type": "All User Profile" if "All User" in line else "User Profile",
                            "has_saved_credentials": True,
                        })
    except Exception as err:
        # Graceful fallback if not on Windows or netsh unavailable
        pass

    return profiles


def recover_local_wifi_password(ssid: str) -> Dict[str, Any]:
    """
    Recovers the locally stored Wi-Fi key for a specific profile on the user's own machine
    using 'netsh wlan show profile name="<SSID>" key=clear'.
    PRIVACY GUARANTEE: The recovered key is returned ephemerally to the caller and is NEVER logged.
    """
    clean_ssid = ssid.strip()
    result = {
        "ssid": clean_ssid,
        "recovered": False,
        "password": None,
        "security_type": "WPA2-Personal",
        "cipher": "CCMP (AES)",
        "message": "Credential recovery requires authenticated local Windows profile permissions."
    }

    if not clean_ssid:
        result["message"] = "Invalid or empty SSID provided."
        return result

    try:
        cmd = ["netsh", "wlan", "show", "profile", f"name={clean_ssid}", "key=clear"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=8)
        if proc.returncode != 0:
            result["message"] = f"Failed to inspect profile '{clean_ssid}'. Ensure the profile exists on this computer."
            return result

        output = proc.stdout
        # Extract Authentication / Security Type
        auth_match = re.search(r"Authentication\s*:\s*(.+)", output)
        if auth_match:
            result["security_type"] = auth_match.group(1).strip()

        # Extract Cipher
        cipher_match = re.search(r"Cipher\s*:\s*(.+)", output)
        if cipher_match:
            result["cipher"] = cipher_match.group(1).strip()

        # Extract Key Content (the saved password)
        key_match = re.search(r"Key Content\s*:\s*(.+)", output)
        if key_match:
            recovered_key = key_match.group(1).strip()
            result["recovered"] = True
            result["password"] = recovered_key
            result["message"] = "Local password successfully recovered from Windows credential vault."
        else:
            result["message"] = "Profile exists, but no unencrypted PSK key is stored (e.g. 802.1X Enterprise certificate)."

    except Exception as err:
        result["message"] = f"Local recovery error: {str(err)}"

    return result


def audit_password_strength_offline(password: str) -> Dict[str, Any]:
    """
    Performs deterministic offline password strength analysis.
    Evaluates:
      - Length
      - Character diversity (upper, lower, digits, symbols)
      - Shannon entropy in bits
      - Common password dictionary detection
      - Predictability patterns
    """
    pwd = password or ""
    length = len(pwd)
    has_lower = bool(re.search(r"[a-z]", pwd))
    has_upper = bool(re.search(r"[A-Z]", pwd))
    has_digits = bool(re.search(r"\d", pwd))
    has_symbols = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\+=]", pwd))

    # 1. Pool size calculation
    pool_size = 0
    if has_lower: pool_size += 26
    if has_upper: pool_size += 26
    if has_digits: pool_size += 10
    if has_symbols: pool_size += 33
    pool_size = max(pool_size, 1)

    # 2. Shannon entropy calculation
    # Entropy = length * log2(pool_size)
    entropy_bits = round(length * math.log2(pool_size), 1) if length > 0 else 0.0

    # 3. Common password check
    is_common = pwd.lower() in COMMON_WEAK_PASSWORDS

    # 4. Scoring logic (0 to 100)
    score = 0
    if length >= 8: score += 20
    if length >= 12: score += 15
    if length >= 16: score += 15
    if has_lower and has_upper: score += 15
    if has_digits: score += 15
    if has_symbols: score += 20

    # Penalties
    if is_common:
        score = min(score, 20)
    if length < 8:
        score = min(score, 30)

    # Categorization
    if score >= 85 and entropy_bits >= 70:
        strength = "Very Strong"
        color = "green"
    elif score >= 65 and entropy_bits >= 50:
        strength = "Strong"
        color = "emerald"
    elif score >= 45:
        strength = "Moderate"
        color = "amber"
    else:
        strength = "Weak"
        color = "red"

    # Actionable recommendations
    recommendations = []
    if length < 12:
        recommendations.append("Increase length to at least 12–16 characters.")
    if not (has_lower and has_upper):
        recommendations.append("Mix uppercase and lowercase letters.")
    if not has_digits:
        recommendations.append("Include numeric digits (0–9).")
    if not has_symbols:
        recommendations.append("Include special characters (e.g., !@#$%^&*).")
    if is_common:
        recommendations.append("This password appears in common attack dictionaries. Choose a unique passphrase immediately.")
    if not recommendations:
        recommendations.append("Excellent password complexity. Follow recommended rotation practices every 90–180 days.")

    return {
        "length": length,
        "has_lowercase": has_lower,
        "has_uppercase": has_upper,
        "has_digits": has_digits,
        "has_symbols": has_symbols,
        "entropy_bits": entropy_bits,
        "is_common_dictionary_match": is_common,
        "score": score,
        "strength": strength,
        "color": color,
        "recommendations": recommendations,
    }


def generate_strong_wifi_passphrase(length: int = 16) -> str:
    """Generates a cryptographically strong, random Wi-Fi passphrase."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    # Ensure at least one of each category
    while True:
        candidate = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in candidate) and
            any(c.isupper() for c in candidate) and
            any(c.isdigit() for c in candidate) and
            any(c in "!@#$%^&*" for c in candidate)):
            return candidate


def analyze_wireless_security_posture(
    ssid: str,
    security_protocol: str,
    cipher: str,
    wps_enabled: bool = False,
    password_score: Optional[int] = None,
) -> Dict[str, Any]:
    """
    Performs defensive wireless architecture analysis:
    Flags deprecated WEP, WPA1, TKIP, WPS vulnerabilities, or weak pre-shared keys.
    """
    findings: List[Dict[str, Any]] = []
    overall_rating = "SECURE"

    clean_proto = security_protocol.upper()
    clean_cipher = cipher.upper()

    # 1. Deprecated Encryption Checks
    if "WEP" in clean_proto:
        findings.append({
            "title": "Deprecated WEP (Wired Equivalent Privacy) Protocol Detected",
            "severity": "Critical",
            "impact": "WEP uses broken RC4 stream cipher and weak IVs. Attackers can recover keys in minutes.",
            "remediation": "Upgrade router security mode to WPA2-Personal (AES) or WPA3-Personal immediately."
        })
        overall_rating = "CRITICAL_RISK"

    elif "WPA" in clean_proto and "WPA2" not in clean_proto and "WPA3" not in clean_proto:
        findings.append({
            "title": "Legacy WPA1 Protocol In Use",
            "severity": "High",
            "impact": "WPA1 is vulnerable to Beck-Tews and Ohigashi-Kuwakado attacks.",
            "remediation": "Configure Wi-Fi router to enforce WPA2-PSK (AES) or WPA3-SAE only."
        })
        overall_rating = "HIGH_RISK"

    # 2. Cipher Inspection
    if "TKIP" in clean_cipher:
        findings.append({
            "title": "Deprecated TKIP (Temporal Key Integrity Protocol) Cipher Enabled",
            "severity": "High",
            "impact": "TKIP has known cryptographic weaknesses and throttles 802.11n/ac transmission speeds.",
            "remediation": "Disable TKIP in router wireless configuration; enable CCMP / AES encryption exclusively."
        })
        if overall_rating == "SECURE":
            overall_rating = "ELEVATED_RISK"

    # 3. WPS Posture Check
    if wps_enabled:
        findings.append({
            "title": "Wi-Fi Protected Setup (WPS) PIN Authentication Enabled",
            "severity": "High",
            "impact": "WPS PINs can be brute-forced via offline and online PIN attacks (Reaver / Pixie Dust).",
            "remediation": "Disable WPS in router management console. Use strong WPA2/WPA3 passphrase entry instead."
        })
        if overall_rating == "SECURE":
            overall_rating = "ELEVATED_RISK"

    # 4. Password Strength Finding
    if password_score is not None and password_score < 50:
        findings.append({
            "title": "Weak Wireless Pre-Shared Key (PSK)",
            "severity": "Medium",
            "impact": "Weak passwords allow fast offline dictionary matching if an attacker captures the 4-way handshake.",
            "remediation": "Update Wi-Fi passphrase to 16+ characters with mixed case, digits, and symbols."
        })

    # Architecture Recommendations
    recommendations = [
        "Enable Client Isolation (AP Isolation) on Guest Wi-Fi networks so visitors cannot inspect local devices.",
        "Change the default router administrator password from 'admin' or factory defaults.",
        "Keep router firmware updated with automatic security patches enabled.",
        "Disable remote WAN web administration to prevent exposure to internet scanners.",
    ]

    return {
        "ssid": ssid,
        "security_protocol": security_protocol,
        "cipher": cipher,
        "wps_enabled": wps_enabled,
        "overall_posture": overall_rating,
        "findings": findings,
        "findings_count": len(findings),
        "defensive_recommendations": recommendations,
        "verified_evidence": f"Wireless interface query: Protocol={security_protocol}, Cipher={cipher}, WPS={wps_enabled}",
    }
