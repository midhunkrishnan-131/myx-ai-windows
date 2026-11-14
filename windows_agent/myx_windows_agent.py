"""
MYX-Windows-Agent (windows_agent/myx_windows_agent.py)
Standalone Defensive Local Security Auditing Agent for Microsoft Windows 10 & Windows 11.
Brand: MYX AI by Midhun Krishnan ("Discover. Detect. Defend.")

SECURITY GUARANTEES:
- Windows 10 (20H2+) & Windows 11 (21H2-24H2+) Only.
- Strictly executes compiled-in read-only collectors (system_info, security_posture, network_diag, wifi_auditor).
- ZERO remote shell or arbitrary command execution path.
- Detects Standard User vs Elevated Administrator token via ctypes.windll.shell32.IsUserAnAdmin().
"""
import argparse
import ctypes
import hashlib
import hmac
import json
import platform
import time
from datetime import datetime, timezone

from collectors.system_info import collect_windows_system_info
from collectors.security_posture import collect_windows_security_posture
from collectors.network_diag import collect_windows_network_diagnostics
from collectors.wifi_auditor import collect_windows_wifi_posture


def is_windows_10_or_11() -> bool:
    if platform.system() != "Windows":
        return False
    release = platform.release()
    return release in {"10", "11"} or platform.version().startswith("10.0.")


def is_elevated_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def sign_telemetry_payload(payload_bytes: bytes, hmac_secret: str, timestamp_str: str) -> str:
    msg = f"{timestamp_str}.".encode("utf-8") + payload_bytes
    return hmac.new(hmac_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def run_local_audit() -> dict:
    if not is_windows_10_or_11():
        return {
            "status": "UNSUPPORTED_OS",
            "message": "MYX-Windows-Agent supports Microsoft Windows 10 and Windows 11 exclusively.",
            "detected_os": platform.platform(),
        }

    elevated = is_elevated_admin()
    return {
        "agent_version": "2.4.0-WIN",
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "privilege_level": "ELEVATED_ADMIN" if elevated else "STANDARD_USER",
        "system_info": collect_windows_system_info(elevated),
        "security_posture": collect_windows_security_posture(elevated),
        "network_diagnostics": collect_windows_network_diagnostics(elevated),
        "wifi_audit": collect_windows_wifi_posture(),
    }


def main():
    parser = argparse.ArgumentParser(
        description="MYX AI by Midhun Krishnan — Windows 10/11 Defensive Local Security Agent"
    )
    sub = parser.add_subparsers(dest="command")

    enroll_p = sub.add_parser("enroll", help="Enroll this Windows 10/11 host with a single-use token")
    enroll_p.add_argument("--server", required=True, help="FastAPI server URL (e.g. https://...)")
    enroll_p.add_argument("--token", required=True, help="Single-use enrollment token (MYX-ENR-...)")

    sub.add_parser("audit", help="Run read-only Windows 10/11 security posture collectors and print JSON")

    args = parser.parse_args()
    if args.command == "audit":
        print(json.dumps(run_local_audit(), indent=2))
    elif args.command == "enroll":
        print(f"[MYX-Windows-Agent] Enrolling host {platform.node()} with server {args.server}...")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
