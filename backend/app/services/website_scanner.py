"""
MYX AI (Windows Edition) — Advanced Website Security Assessment Engine.
Performs genuine, non-destructive HTTP security header audits, redirect chain inspection,
cookie security analysis, and transparent weighted scoring.
"""
import time
import urllib.parse
from typing import Dict, Any, List, Optional
import httpx

from app.security.ssrf_guard import validate_and_resolve_target_url, SsrfBlockedError

# Weights sum to exactly 100 points
CONTROL_WEIGHTS = {
    "MYX-CTRL-CSP-01": {"name": "Content-Security-Policy", "weight": 20, "cwe": "CWE-1021", "category": "HTTP Security Headers"},
    "MYX-CTRL-HSTS-02": {"name": "Strict-Transport-Security (HSTS)", "weight": 15, "cwe": "CWE-319", "category": "Transport Security"},
    "MYX-CTRL-XFO-03": {"name": "Clickjacking Defense (XFO & frame-ancestors)", "weight": 15, "cwe": "CWE-1021", "category": "HTTP Security Headers"},
    "MYX-CTRL-COOKIE-04": {"name": "Set-Cookie Security Attributes", "weight": 12, "cwe": "CWE-614", "category": "Session & Cookie Security"},
    "MYX-CTRL-XCTO-05": {"name": "X-Content-Type-Options: nosniff", "weight": 10, "cwe": "CWE-430", "category": "HTTP Security Headers"},
    "MYX-CTRL-RP-06": {"name": "Referrer-Policy", "weight": 10, "cwe": "CWE-200", "category": "Privacy & Referrer"},
    "MYX-CTRL-PERM-07": {"name": "Permissions-Policy Hardware Governance", "weight": 8, "cwe": "CWE-693", "category": "Privacy & Browser Capabilities"},
    "MYX-CTRL-INFO-08": {"name": "Server Banner & Information Disclosure", "weight": 5, "cwe": "CWE-200", "category": "Information Exposure"},
    "MYX-CTRL-TRANS-09": {"name": "HTTPS Redirection & Transport Integrity", "weight": 5, "cwe": "CWE-319", "category": "Transport Security"},
}


def evaluate_security_headers_and_score(
    final_url: str,
    status_code: int,
    headers: Dict[str, str],
    redirect_chain: List[Dict[str, Any]],
    raw_cookies: List[str],
    is_demo_preview: bool = False,
) -> Dict[str, Any]:
    """
    Evaluates observed HTTP headers against the 9 defensive security controls
    using a transparent, non-arbitrary weighted scoring model.
    """
    results: List[Dict[str, Any]] = []

    # 1. Content-Security-Policy (Weight: 20)
    csp_val = headers.get("content-security-policy") or headers.get("content-security-policy-report-only") or ""
    ctrl_csp = CONTROL_WEIGHTS["MYX-CTRL-CSP-01"]
    if not csp_val:
        results.append({
            "control_id": "MYX-CTRL-CSP-01",
            "check_code": "WEB-CSP-001",
            "check_title": "Content-Security-Policy (CSP) Missing",
            "category": ctrl_csp["category"],
            "status": "FAIL",
            "severity": "High",
            "confidence": "Confirmed",
            "weight": ctrl_csp["weight"],
            "points_earned": 0,
            "points_deducted": 20,
            "actual_header_observed": "Content-Security-Policy: (absent)",
            "expected_configuration": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';",
            "technical_explanation": "The target website did not return a Content-Security-Policy header. Browsers will execute any inline scripts and load external resources from any origin, significantly increasing vulnerability to Cross-Site Scripting (XSS).",
            "remediation_recommendation": "Deploy a strict Content-Security-Policy specifying default-src 'self', explicit script sources with cryptographic nonces, and object-src 'none'.",
            "cwe_id": ctrl_csp["cwe"],
        })
    else:
        # Nuanced evaluation: check if only upgrade-insecure-requests is present
        csp_lower = csp_val.lower()
        has_upgrade_only = "upgrade-insecure-requests" in csp_lower and not any(
            d in csp_lower for d in ["default-src", "script-src", "frame-ancestors", "connect-src"]
        )
        has_unsafe = "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower or "script-src *" in csp_lower

        if has_upgrade_only:
            results.append({
                "control_id": "MYX-CTRL-CSP-01",
                "check_code": "WEB-CSP-001",
                "check_title": "Content-Security-Policy Contains Only upgrade-insecure-requests",
                "category": ctrl_csp["category"],
                "status": "WARNING",
                "severity": "Medium",
                "confidence": "Confirmed",
                "weight": ctrl_csp["weight"],
                "points_earned": 10,
                "points_deducted": 10,
                "actual_header_observed": f"Content-Security-Policy: {csp_val[:200]}",
                "expected_configuration": "default-src 'self'; script-src 'self'; object-src 'none';",
                "technical_explanation": "The Content-Security-Policy contains 'upgrade-insecure-requests' which enforces HTTPS resource loading, but lacks restrictive directives (default-src, script-src) to prevent arbitrary JavaScript execution or injection.",
                "remediation_recommendation": "Expand the policy to declare default-src 'self', script-src with nonces/hashes, and object-src 'none'.",
                "cwe_id": ctrl_csp["cwe"],
            })
        elif has_unsafe:
            results.append({
                "control_id": "MYX-CTRL-CSP-01",
                "check_code": "WEB-CSP-001",
                "check_title": "Content-Security-Policy Contains Permissive Directives (unsafe-inline / unsafe-eval / wildcard)",
                "category": ctrl_csp["category"],
                "status": "WARNING",
                "severity": "Medium",
                "confidence": "Confirmed",
                "weight": ctrl_csp["weight"],
                "points_earned": 10,
                "points_deducted": 10,
                "actual_header_observed": f"Content-Security-Policy: {csp_val[:250]}...",
                "expected_configuration": "Remove 'unsafe-inline' and 'unsafe-eval'; migrate to nonce-based or hash-based script execution.",
                "technical_explanation": "Directives allowing 'unsafe-inline' or wildcard '*' allow injected script tags or inline handlers to execute unrestricted, weakening XSS defense.",
                "remediation_recommendation": "Refactor inline scripts into external bundles with cryptographic nonces (nonce-rAnd0m) or SHA-256 hashes.",
                "cwe_id": ctrl_csp["cwe"],
            })
        else:
            results.append({
                "control_id": "MYX-CTRL-CSP-01",
                "check_code": "WEB-CSP-001",
                "check_title": "Content-Security-Policy (CSP) Actively Enforced",
                "category": ctrl_csp["category"],
                "status": "PASS",
                "severity": "Informational",
                "confidence": "Confirmed",
                "weight": ctrl_csp["weight"],
                "points_earned": 20,
                "points_deducted": 0,
                "actual_header_observed": f"Content-Security-Policy: {csp_val[:200]}...",
                "expected_configuration": "Enforced restrictive policy active.",
                "technical_explanation": "A structured Content-Security-Policy was detected restricting resource origins and execution contexts.",
                "remediation_recommendation": "Maintain regular audit of policy directives against newly integrated 3rd-party assets.",
                "cwe_id": ctrl_csp["cwe"],
            })

    # 2. Strict-Transport-Security (HSTS) (Weight: 15)
    # Check on the final HTTPS endpoint
    ctrl_hsts = CONTROL_WEIGHTS["MYX-CTRL-HSTS-02"]
    is_https = final_url.lower().startswith("https://")
    hsts_val = headers.get("strict-transport-security") or ""

    if not is_https:
        results.append({
            "control_id": "MYX-CTRL-HSTS-02",
            "check_code": "WEB-HSTS-002",
            "check_title": "Strict-Transport-Security (HSTS) Not Applicable on Insecure HTTP",
            "category": ctrl_hsts["category"],
            "status": "FAIL",
            "severity": "High",
            "confidence": "Confirmed",
            "weight": ctrl_hsts["weight"],
            "points_earned": 0,
            "points_deducted": 15,
            "actual_header_observed": f"Final URL scheme is plaintext HTTP ({final_url})",
            "expected_configuration": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "technical_explanation": "HSTS cannot be enforced on unencrypted HTTP connections. Browsers ignore HSTS headers received over plaintext HTTP.",
            "remediation_recommendation": "Migrate the target service to HTTPS and configure strict redirection from port 80 to 443.",
            "cwe_id": ctrl_hsts["cwe"],
        })
    elif not hsts_val:
        results.append({
            "control_id": "MYX-CTRL-HSTS-02",
            "check_code": "WEB-HSTS-002",
            "check_title": "Strict-Transport-Security (HSTS) Header Absent on HTTPS Endpoint",
            "category": ctrl_hsts["category"],
            "status": "FAIL",
            "severity": "High",
            "confidence": "Confirmed",
            "weight": ctrl_hsts["weight"],
            "points_earned": 0,
            "points_deducted": 15,
            "actual_header_observed": "Strict-Transport-Security: (absent on final HTTPS response)",
            "expected_configuration": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            "technical_explanation": "HTTPS connection is active, but the server does not instruct browsers to remember HTTPS via HSTS. Users remain vulnerable to SSL stripping attacks on initial visit.",
            "remediation_recommendation": "Configure web server or reverse proxy to return 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'.",
            "cwe_id": ctrl_hsts["cwe"],
        })
    else:
        # Check max-age, includeSubDomains, preload
        hsts_lower = hsts_val.lower()
        max_age = 0
        for token in hsts_lower.split(";"):
            t = token.strip()
            if t.startswith("max-age="):
                try:
                    max_age = int(t.split("=")[1])
                except ValueError:
                    max_age = 0

        has_subdomains = "includesubdomains" in hsts_lower
        has_preload = "preload" in hsts_lower

        if max_age < 31536000 or not has_subdomains:
            results.append({
                "control_id": "MYX-CTRL-HSTS-02",
                "check_code": "WEB-HSTS-002",
                "check_title": "Strict-Transport-Security (HSTS) Active with Low max-age or Missing includeSubDomains",
                "category": ctrl_hsts["category"],
                "status": "WARNING",
                "severity": "Medium",
                "confidence": "Confirmed",
                "weight": ctrl_hsts["weight"],
                "points_earned": 8,
                "points_deducted": 7,
                "actual_header_observed": f"Strict-Transport-Security: {hsts_val}",
                "expected_configuration": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "technical_explanation": f"HSTS is present, but max-age ({max_age} seconds) is less than the 1-year standard (31536000), or 'includeSubDomains' is missing.",
                "remediation_recommendation": "Increase max-age to at least 31536000 seconds (1 year) and includeSubDomains to protect all subdomains from interception.",
                "cwe_id": ctrl_hsts["cwe"],
            })
        else:
            results.append({
                "control_id": "MYX-CTRL-HSTS-02",
                "check_code": "WEB-HSTS-002",
                "check_title": "Strict-Transport-Security (HSTS) Enforced with Strong Policy",
                "category": ctrl_hsts["category"],
                "status": "PASS",
                "severity": "Informational",
                "confidence": "Confirmed",
                "weight": ctrl_hsts["weight"],
                "points_earned": 15,
                "points_deducted": 0,
                "actual_header_observed": f"Strict-Transport-Security: {hsts_val}",
                "expected_configuration": "HSTS properly configured (max-age >= 31536000, includeSubDomains).",
                "technical_explanation": f"Robust HSTS policy configured (max-age: {max_age}s, includeSubDomains: {has_subdomains}, preload: {has_preload}).",
                "remediation_recommendation": "HSTS complies with industry standards. Maintain inclusion in Chromium HSTS preload list if eligible.",
                "cwe_id": ctrl_hsts["cwe"],
            })

    # 3. Clickjacking Defense (XFO & frame-ancestors) (Weight: 15)
    ctrl_xfo = CONTROL_WEIGHTS["MYX-CTRL-XFO-03"]
    xfo_val = headers.get("x-frame-options") or ""
    has_frame_ancestors = "frame-ancestors" in csp_val.lower()

    if not xfo_val and not has_frame_ancestors:
        results.append({
            "control_id": "MYX-CTRL-XFO-03",
            "check_code": "WEB-XFO-003",
            "check_title": "Missing Clickjacking Defense (Neither X-Frame-Options nor CSP frame-ancestors)",
            "category": ctrl_xfo["category"],
            "status": "FAIL",
            "severity": "Medium",
            "confidence": "Confirmed",
            "weight": ctrl_xfo["weight"],
            "points_earned": 0,
            "points_deducted": 15,
            "actual_header_observed": "Neither X-Frame-Options nor frame-ancestors returned.",
            "expected_configuration": "X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors 'none' / 'self')",
            "technical_explanation": "Adversaries can embed this website within an invisible <iframe> on an attacker-controlled origin to trick authenticated users into clicking buttons or triggering transactions (UI redressing).",
            "remediation_recommendation": "Configure 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self'' to restrict framing.",
            "cwe_id": ctrl_xfo["cwe"],
        })
    else:
        obs = f"X-Frame-Options: {xfo_val}" if xfo_val else "CSP frame-ancestors active"
        results.append({
            "control_id": "MYX-CTRL-XFO-03",
            "check_code": "WEB-XFO-003",
            "check_title": "Clickjacking Protection Actively Enforced",
            "category": ctrl_xfo["category"],
            "status": "PASS",
            "severity": "Informational",
            "confidence": "Confirmed",
            "weight": ctrl_xfo["weight"],
            "points_earned": 15,
            "points_deducted": 0,
            "actual_header_observed": obs,
            "expected_configuration": "Framing restrictions enforced.",
            "technical_explanation": "The target website instructs user agents to deny unauthorized iframe framing via XFO or CSP frame-ancestors.",
            "remediation_recommendation": "Clickjacking protection is active. Prefer CSP frame-ancestors for fine-grained origin specifications.",
            "cwe_id": ctrl_xfo["cwe"],
        })

    # 4. Set-Cookie Security Attributes (Weight: 12)
    ctrl_cookie = CONTROL_WEIGHTS["MYX-CTRL-COOKIE-04"]
    if not raw_cookies:
        results.append({
            "control_id": "MYX-CTRL-COOKIE-04",
            "check_code": "WEB-CK-004",
            "check_title": "No Cookies Transmitted on Passive Inspection",
            "category": ctrl_cookie["category"],
            "status": "PASS",
            "severity": "Informational",
            "confidence": "Confirmed",
            "weight": ctrl_cookie["weight"],
            "points_earned": 12,
            "points_deducted": 0,
            "actual_header_observed": "Set-Cookie: (none transmitted on target endpoint)",
            "expected_configuration": "Cookies must have Secure; HttpOnly; SameSite=Lax/Strict",
            "technical_explanation": "No HTTP cookies were set during the passive assessment. There are no exposed plaintext or unflagged session tokens on this entry point.",
            "remediation_recommendation": "Ensure any future authentication cookies enforce 'Secure; HttpOnly; SameSite=Lax'.",
            "cwe_id": ctrl_cookie["cwe"],
        })
    else:
        insecure_cookies = []
        for cookie_str in raw_cookies:
            c_lower = cookie_str.lower()
            name = cookie_str.split("=")[0].strip()
            missing = []
            if "secure" not in c_lower:
                missing.append("Secure")
            if "httponly" not in c_lower:
                missing.append("HttpOnly")
            if "samesite" not in c_lower:
                missing.append("SameSite")
            if missing:
                insecure_cookies.append(f"'{name}' missing [{', '.join(missing)}]")

        if insecure_cookies:
            results.append({
                "control_id": "MYX-CTRL-COOKIE-04",
                "check_code": "WEB-CK-004",
                "check_title": "Insecure Cookie Flags (Missing Secure, HttpOnly, or SameSite)",
                "category": ctrl_cookie["category"],
                "status": "WARNING",
                "severity": "Medium",
                "confidence": "Confirmed",
                "weight": ctrl_cookie["weight"],
                "points_earned": 6,
                "points_deducted": 6,
                "actual_header_observed": "; ".join(insecure_cookies[:3]),
                "expected_configuration": "Set-Cookie: ...; Secure; HttpOnly; SameSite=Lax",
                "technical_explanation": "Cookies without Secure can be transmitted over plaintext channels; cookies without HttpOnly can be accessed by malicious JavaScript via document.cookie; cookies without SameSite are susceptible to Cross-Site Request Forgery (CSRF).",
                "remediation_recommendation": "Enforce 'Secure', 'HttpOnly', and 'SameSite=Lax' (or Strict) on all session and application state cookies.",
                "cwe_id": ctrl_cookie["cwe"],
            })
        else:
            results.append({
                "control_id": "MYX-CTRL-COOKIE-04",
                "check_code": "WEB-CK-004",
                "check_title": "Cookie Security Attributes (Secure, HttpOnly, SameSite) Enforced",
                "category": ctrl_cookie["category"],
                "status": "PASS",
                "severity": "Informational",
                "confidence": "Confirmed",
                "weight": ctrl_cookie["weight"],
                "points_earned": 12,
                "points_deducted": 0,
                "actual_header_observed": f"{len(raw_cookies)} cookie(s) inspected, all enforce Secure, HttpOnly, and SameSite.",
                "expected_configuration": "All cookies hardened.",
                "technical_explanation": "All transmitted cookies enforce the necessary browser protection flags.",
                "remediation_recommendation": "Maintain standard cookie hardening across all subdomains and microservice endpoints.",
                "cwe_id": ctrl_cookie["cwe"],
            })

    # 5. X-Content-Type-Options: nosniff (Weight: 10)
    ctrl_xcto = CONTROL_WEIGHTS["MYX-CTRL-XCTO-05"]
    xcto_val = (headers.get("x-content-type-options") or "").strip().lower()
    if "nosniff" not in xcto_val:
        results.append({
            "control_id": "MYX-CTRL-XCTO-05",
            "check_code": "WEB-XCTO-005",
            "check_title": "Missing X-Content-Type-Options: nosniff Header",
            "category": ctrl_xcto["category"],
            "status": "WARNING",
            "severity": "Low",
            "confidence": "Confirmed",
            "weight": ctrl_xcto["weight"],
            "points_earned": 5,
            "points_deducted": 5,
            "actual_header_observed": f"X-Content-Type-Options: {xcto_val or '(absent)'}",
            "expected_configuration": "X-Content-Type-Options: nosniff",
            "technical_explanation": "Without 'nosniff', legacy browsers may ignore the declared Content-Type header and attempt to deduce (MIME-sniff) the payload, potentially executing user-uploaded images or text as HTML/JavaScript.",
            "remediation_recommendation": "Configure web server or proxy to send 'X-Content-Type-Options: nosniff'.",
            "cwe_id": ctrl_xcto["cwe"],
        })
    else:
        results.append({
            "control_id": "MYX-CTRL-XCTO-05",
            "check_code": "WEB-XCTO-005",
            "check_title": "X-Content-Type-Options: nosniff Active",
            "category": ctrl_xcto["category"],
            "status": "PASS",
            "severity": "Informational",
            "confidence": "Confirmed",
            "weight": ctrl_xcto["weight"],
            "points_earned": 10,
            "points_deducted": 0,
            "actual_header_observed": "X-Content-Type-Options: nosniff",
            "expected_configuration": "X-Content-Type-Options: nosniff",
            "technical_explanation": "Browsers are strictly instructed not to MIME-sniff response payloads away from the declared Content-Type.",
            "remediation_recommendation": "Configuration complies with defensive best practices.",
            "cwe_id": ctrl_xcto["cwe"],
        })

    # 6. Referrer-Policy (Weight: 10)
    ctrl_rp = CONTROL_WEIGHTS["MYX-CTRL-RP-06"]
    rp_val = (headers.get("referrer-policy") or "").strip()
    if not rp_val:
        results.append({
            "control_id": "MYX-CTRL-RP-06",
            "check_code": "WEB-RP-006",
            "check_title": "Missing Explicit Referrer-Policy Header",
            "category": ctrl_rp["category"],
            "status": "WARNING",
            "severity": "Low",
            "confidence": "Confirmed",
            "weight": ctrl_rp["weight"],
            "points_earned": 5,
            "points_deducted": 5,
            "actual_header_observed": "Referrer-Policy: (absent)",
            "expected_configuration": "Referrer-Policy: strict-origin-when-cross-origin",
            "technical_explanation": "When Referrer-Policy is omitted, browsers may leak full URL paths and query parameters (potentially including reset tokens or session IDs) in the Referer header to external destinations.",
            "remediation_recommendation": "Declare 'Referrer-Policy: strict-origin-when-cross-origin' to protect query parameter privacy.",
            "cwe_id": ctrl_rp["cwe"],
        })
    else:
        results.append({
            "control_id": "MYX-CTRL-RP-06",
            "check_code": "WEB-RP-006",
            "check_title": "Referrer-Policy Explicitly Governed",
            "category": ctrl_rp["category"],
            "status": "PASS",
            "severity": "Informational",
            "confidence": "Confirmed",
            "weight": ctrl_rp["weight"],
            "points_earned": 10,
            "points_deducted": 0,
            "actual_header_observed": f"Referrer-Policy: {rp_val}",
            "expected_configuration": "Referrer-Policy active.",
            "technical_explanation": f"The target website governs outgoing referrer leakage with policy '{rp_val}'.",
            "remediation_recommendation": "Policy actively mitigates path/token leakage.",
            "cwe_id": ctrl_rp["cwe"],
        })

    # 7. Permissions-Policy (Weight: 8)
    ctrl_perm = CONTROL_WEIGHTS["MYX-CTRL-PERM-07"]
    perm_val = (headers.get("permissions-policy") or "").strip()
    if not perm_val:
        results.append({
            "control_id": "MYX-CTRL-PERM-07",
            "check_code": "WEB-PERM-007",
            "check_title": "Missing Permissions-Policy Header",
            "category": ctrl_perm["category"],
            "status": "WARNING",
            "severity": "Low",
            "confidence": "Confirmed",
            "weight": ctrl_perm["weight"],
            "points_earned": 4,
            "points_deducted": 4,
            "actual_header_observed": "Permissions-Policy: (absent)",
            "expected_configuration": "Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()",
            "technical_explanation": "Hardware and sensitive browser capabilities (microphone, camera, geolocation, payments) are not explicitly disabled, allowing embedded third-party scripts to access device hardware if user grants permission.",
            "remediation_recommendation": "Configure 'Permissions-Policy: camera=(), microphone=(), geolocation=()' to disable unnecessary browser APIs.",
            "cwe_id": ctrl_perm["cwe"],
        })
    else:
        results.append({
            "control_id": "MYX-CTRL-PERM-07",
            "check_code": "WEB-PERM-007",
            "check_title": "Permissions-Policy Hardware Access Governed",
            "category": ctrl_perm["category"],
            "status": "PASS",
            "severity": "Informational",
            "confidence": "Confirmed",
            "weight": ctrl_perm["weight"],
            "points_earned": 8,
            "points_deducted": 0,
            "actual_header_observed": f"Permissions-Policy: {perm_val[:200]}...",
            "expected_configuration": "Permissions-Policy declared.",
            "technical_explanation": "Browser hardware APIs and device sensors are explicitly restricted.",
            "remediation_recommendation": "Policy conforms to defensive standards.",
            "cwe_id": ctrl_perm["cwe"],
        })

    # 8. Server Banner & Information Disclosure (Weight: 5)
    ctrl_info = CONTROL_WEIGHTS["MYX-CTRL-INFO-08"]
    srv = headers.get("server") or ""
    pby = headers.get("x-powered-by") or headers.get("x-aspnet-version") or ""
    has_leakage = False
    leak_details = []
    if srv and any(c.isdigit() for c in srv):
        has_leakage = True
        leak_details.append(f"Server: {srv}")
    if pby:
        has_leakage = True
        leak_details.append(f"X-Powered-By: {pby}")

    if has_leakage:
        results.append({
            "control_id": "MYX-CTRL-INFO-08",
            "check_code": "WEB-EXP-008",
            "check_title": "Server Banner or Technology Version Disclosure",
            "category": ctrl_info["category"],
            "status": "WARNING",
            "severity": "Low",
            "confidence": "Confirmed",
            "weight": ctrl_info["weight"],
            "points_earned": 2,
            "points_deducted": 3,
            "actual_header_observed": "; ".join(leak_details),
            "expected_configuration": "Server banners suppressed or generic (e.g. Server: cloudflare / proxy).",
            "technical_explanation": "Detailed web server or framework versions assist attackers in reconnaissance and target-specific automated exploit selection.",
            "remediation_recommendation": "Disable technology banners (e.g. server_tokens off in nginx, app.disable('x-powered-by') in Express).",
            "cwe_id": ctrl_info["cwe"],
        })
    else:
        results.append({
            "control_id": "MYX-CTRL-INFO-08",
            "check_code": "WEB-EXP-008",
            "check_title": "Server Software Banners Suppressed or Sanitized",
            "category": ctrl_info["category"],
            "status": "PASS",
            "severity": "Informational",
            "confidence": "Confirmed",
            "weight": ctrl_info["weight"],
            "points_earned": 5,
            "points_deducted": 0,
            "actual_header_observed": f"Server: {srv or '(suppressed)'}; Powered-By: (none)",
            "expected_configuration": "Banners minimized.",
            "technical_explanation": "No sensitive software version numbers or technology stacks are leaked via HTTP headers.",
            "remediation_recommendation": "Maintained defensive banner suppression.",
            "cwe_id": ctrl_info["cwe"],
        })

    # 9. HTTPS Transport & Redirection Integrity (Weight: 5)
    ctrl_trans = CONTROL_WEIGHTS["MYX-CTRL-TRANS-09"]
    final_is_https = final_url.lower().startswith("https://")
    has_downgrade = any(
        step.get("from", "").startswith("https://") and step.get("to", "").startswith("http://")
        for step in redirect_chain
    )

    if not final_is_https or has_downgrade:
        results.append({
            "control_id": "MYX-CTRL-TRANS-09",
            "check_code": "WEB-TRANS-009",
            "check_title": "Insecure Transport Protocol or HTTPS Downgrade Detected",
            "category": ctrl_trans["category"],
            "status": "FAIL",
            "severity": "High",
            "confidence": "Confirmed",
            "weight": ctrl_trans["weight"],
            "points_earned": 0,
            "points_deducted": 5,
            "actual_header_observed": f"Final URL: {final_url}; Downgrade detected: {has_downgrade}",
            "expected_configuration": "Enforce HTTPS redirect with 301/308; never downgrade to HTTP.",
            "technical_explanation": "The target website serves plaintext HTTP traffic or downgrades from HTTPS to plaintext HTTP in its redirect chain.",
            "remediation_recommendation": "Enforce strict permanent redirect to HTTPS and reject unencrypted HTTP traffic.",
            "cwe_id": ctrl_trans["cwe"],
        })
    else:
        redirect_summary = f"{len(redirect_chain)} redirect(s) followed" if redirect_chain else "Direct HTTPS connection"
        results.append({
            "control_id": "MYX-CTRL-TRANS-09",
            "check_code": "WEB-TRANS-009",
            "check_title": "HTTPS Transport Protocol & Redirect Integrity Verified",
            "category": ctrl_trans["category"],
            "status": "PASS",
            "severity": "Informational",
            "confidence": "Confirmed",
            "weight": ctrl_trans["weight"],
            "points_earned": 5,
            "points_deducted": 0,
            "actual_header_observed": f"Final URL: {final_url} ({redirect_summary})",
            "expected_configuration": "Direct or redirected to HTTPS.",
            "technical_explanation": "Connection securely terminates on HTTPS without protocol downgrade.",
            "remediation_recommendation": "Transport integrity verified.",
            "cwe_id": ctrl_trans["cwe"],
        })

    # Score Calculation: Sum of earned points
    total_earned = sum(r["points_earned"] for r in results)
    final_score = max(0, min(100, round(total_earned)))

    now_ts = int(time.time() * 1000)
    for idx, r in enumerate(results):
        if not r.get("id"):
            r["id"] = f"chk-{r.get('control_id', 'ctrl').lower()}-{now_ts}-{idx}"
        if not r.get("raw_evidence"):
            r["raw_evidence"] = f"{r.get('actual_header_observed', '')}\nExpected: {r.get('expected_configuration', '')}".strip()
        if not r.get("remediation_text"):
            r["remediation_text"] = r.get("remediation_recommendation", "")

    passed_count = sum(1 for r in results if r["status"] == "PASS")
    warnings_count = sum(1 for r in results if r["status"] == "WARNING")
    failed_count = sum(1 for r in results if r["status"] == "FAIL")

    return {
        "score": final_score,
        "results": results,
        "summary": {
            "total_checks": len(results),
            "passed": passed_count,
            "warnings": warnings_count,
            "failed": failed_count,
            "requires_elevation": 0,
        },
        "score_breakdown": {
            "max_possible_points": 100,
            "earned_points": final_score,
            "deducted_points": 100 - final_score,
            "weights": CONTROL_WEIGHTS,
        },
    }
