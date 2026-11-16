# MYX AI Network Trust Intelligence — Windows Deployment Guide

## 1. Prerequisites
- **Operating System:** Microsoft Windows 10 (20H2+) or Windows 11 (21H2–24H2+).
- **Architecture:** x64 / ARM64.
- **Node.js:** v18.0.0 or higher.
- **Python:** 3.10 to 3.13 (in `backend/.venv`).

---

## 2. Administrator Elevation Requirements
Applying scoped Windows Defender Firewall containment via `NetSecurity` or `netsh advfirewall` requires elevated administrator privileges:
- When running the standalone agent: right-click and select **"Run as Administrator"**.
- If executed as a standard user: the system monitors telemetry, evaluates deterministic risk, and provides alerts, but prompts the user to disconnect manually rather than attempting unauthorized privileged modifications.

---

## 3. Starting the Platform

### Terminal 1: Full-Stack Platform Server (Express Gateway & Vite Frontend)
```powershell
npm run dev
```
Listens on `http://localhost:3000`.

### Terminal 2: Analytical Backend (FastAPI, Optional for RAG & ReportLab)
```powershell
.\backend\.venv\Scripts\uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Listens on `http://127.0.0.1:8000`.

---

## 4. Emergency Recovery Procedures
If network isolation persists after testing:
1. Run `windows_agent\emergency_release.bat` as Administrator.
2. Or execute PowerShell command:
   ```powershell
   Get-NetFirewallRule -Name "MYX_AI_NTI_*" | Remove-NetFirewallRule
   ```
3. Verify state file removal in `C:\ProgramData\MYX_AI\quarantine_state.json`.
