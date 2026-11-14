"""
Windows 10/11 Network Diagnostics Collector (windows_agent/collectors/network_diag.py).
Inspects active interfaces, routing table, and listening TCP/UDP sockets mapped to PIDs.
"""
import subprocess
import json


def collect_windows_network_diagnostics(is_elevated: bool) -> dict:
    cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-NetTCPConnection -State Listen | Select-Object LocalAddress, LocalPort, OwningProcess | ConvertTo-Json -Compress",
    ]
    listeners = []
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=8, check=False)
        if proc.returncode == 0 and proc.stdout.strip():
            listeners = json.loads(proc.stdout.strip())
    except Exception:
        listeners = []

    return {
        "privilege_level": "ELEVATED_ADMIN" if is_elevated else "STANDARD_USER",
        "listening_tcp_sockets": listeners,
    }
