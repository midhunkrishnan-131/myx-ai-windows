# MYX-Windows-Agent (Windows 10 & Windows 11 Edition)

**Brand:** MYX AI by Midhun Krishnan ("Discover. Detect. Defend.")

## Supported Operating Systems
- Microsoft Windows 10 (20H2 and later — Home, Pro, Enterprise, Education)
- Microsoft Windows 11 (21H2, 22H2, 23H2, 24H2 and later — Home, Pro, Enterprise, Education)
- **Strict Scope**: Linux and macOS local agents are intentionally excluded.

## Quick Enrollment & Execution (Windows PowerShell)
```powershell
cd windows_agent
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 1. Enroll with a 15-minute single-use token generated in the MYX AI Web UI:
python myx_windows_agent.py enroll --server http://127.0.0.1:8000 --token MYX-ENR-...

# 2. Run a read-only local Windows 10/11 security posture audit:
python myx_windows_agent.py audit
```
