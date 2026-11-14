"""
Defensive Windows 10/11 Wi-Fi Security Auditor Collector (windows_agent/collectors/wifi_auditor.py).
Uses read-only `netsh wlan show interfaces` and `netsh wlan show networks mode=bssid`.
Detects Windows 10 (24H2) / Windows 11 Location permission requirement.
"""
import subprocess


def collect_windows_wifi_posture() -> dict:
    try:
        iface = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True,
            text=True,
            timeout=6,
            check=False,
        )
        bssid = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"],
            capture_output=True,
            text=True,
            timeout=6,
            check=False,
        )
        raw_out = (iface.stdout or "") + "\n" + (bssid.stdout or "")
        location_blocked = "location" in raw_out.lower() or "permission" in raw_out.lower()
        return {
            "location_permission_required": location_blocked,
            "raw_interfaces_output": iface.stdout,
            "raw_bssid_output": bssid.stdout,
        }
    except Exception as exc:
        return {"error": str(exc)}
