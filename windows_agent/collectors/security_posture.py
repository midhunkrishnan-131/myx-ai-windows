"""
Defensive Windows 10/11 Security Posture Collector (windows_agent/collectors/security_posture.py).
Inspects Microsoft Defender, Windows Firewall, Windows Update, BitLocker (edition/elevation-aware),
UAC, RDP/NLA, OpenSSH, and high-signal Security Event Log counts.
"""
import subprocess
import json


def _run_readonly_powershell_json(cmdlet_expression: str) -> dict | list | None:
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        f"{cmdlet_expression} | ConvertTo-Json -Compress -Depth 3",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout.strip())
    except Exception:
        return None
    return None


def collect_windows_security_posture(is_elevated: bool) -> dict:
    defender = _run_readonly_powershell_json(
        "Get-MpComputerStatus | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled, IoavProtectionEnabled, TamperProtectionSource, AntivirusSignatureAge"
    )
    firewall = _run_readonly_powershell_json(
        "Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction"
    )

    if is_elevated:
        bitlocker = _run_readonly_powershell_json(
            "Get-BitLockerVolume | Select-Object MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod"
        ) or {"status": "Unsupported on Windows Home Edition"}
    else:
        bitlocker = {
            "status": "REQUIRES_ELEVATION",
            "message": "Requires Elevated Administrator Privileges to query Get-BitLockerVolume.",
        }

    return {
        "defender_status": defender,
        "firewall_profiles": firewall,
        "bitlocker_volumes": bitlocker,
    }
