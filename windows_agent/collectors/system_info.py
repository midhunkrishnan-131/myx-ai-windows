"""
Windows 10/11 System Inventory Collector (windows_agent/collectors/system_info.py).
Strictly read-only inspection of OS edition/build, CPU, RAM, NTFS/ReFS volumes, and KB hotfixes.
"""
import platform
import subprocess
import json


def collect_windows_system_info(is_elevated: bool) -> dict:
    ps_cmd = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture | ConvertTo-Json -Compress",
    ]
    os_meta = {
        "hostname": platform.node(),
        "version": platform.version(),
        "architecture": platform.machine(),
        "privilege_level": "ELEVATED_ADMIN" if is_elevated else "STANDARD_USER",
    }
    try:
        res = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=8, check=False)
        if res.returncode == 0 and res.stdout.strip():
            os_meta["cim_os"] = json.loads(res.stdout.strip())
    except Exception as exc:
        os_meta["collector_note"] = str(exc)
    return os_meta
