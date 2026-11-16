@echo off
REM ============================================================================
REM MYX AI Network Trust Intelligence — Standalone Emergency Quarantine Release
REM Author: Midhun Krishnan | Brand: Discover. Detect. Defend.
REM Strictly removes MYX_AI_NTI_* Windows Defender Firewall rules and watchdog task.
REM Requires Administrator privileges.
REM ============================================================================

echo [MYX AI] Initiating Standalone Emergency Quarantine Release...
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Administrative permissions required. Please right-click and 'Run as Administrator'.
    pause
    exit /b 1
)

echo [MYX AI] Removing scoped quarantine firewall rules...
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Get-NetFirewallRule -Name 'MYX_AI_NTI_*' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; Write-Output 'Firewall rules matching MYX_AI_NTI_* removed cleanly.'"

echo [MYX AI] Cancelling Task Scheduler watchdog...
schtasks.exe /Delete /TN "MYX_AI_NTI_QuarantineWatchdog" /F >nul 2>&1

echo [MYX AI] Clearing disk quarantine state...
if exist "C:\ProgramData\MYX_AI\quarantine_state.json" del /F /Q "C:\ProgramData\MYX_AI\quarantine_state.json" >nul 2>&1

echo ============================================================================
echo [SUCCESS] Emergency release complete. Network connectivity restored.
echo ============================================================================
pause
