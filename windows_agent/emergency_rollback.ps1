# ==============================================================================
# MYX AI Network Trust Intelligence — PowerShell Emergency Rollback Script
# Author: Midhun Krishnan | Brand: Discover. Detect. Defend.
# Invoked by Windows Task Scheduler Watchdog or Emergency CLI
# ==============================================================================

[CmdletBinding()]
param()

Write-Output "[MYX AI] Checking for active MYX_AI_NTI_* quarantine rules..."

try {
    $rules = Get-NetFirewallRule -Name "MYX_AI_NTI_*" -ErrorAction SilentlyContinue
    if ($rules) {
        $count = ($rules | Measure-Object).Count
        Write-Output "[MYX AI] Removing $count scoped quarantine firewall rules..."
        $rules | Remove-NetFirewallRule -ErrorAction SilentlyContinue
        Write-Output "[MYX AI] Rollback completed successfully."
    } else {
        Write-Output "[MYX AI] No active quarantine rules found. Host is already clean."
    }
} catch {
    Write-Warning "[MYX AI] Error removing NetFirewallRule: $_"
}

# Update state file
$statePath = "$env:ProgramData\MYX_AI\quarantine_state.json"
if (Test-Path $statePath) {
    try {
        $json = Get-Content $statePath -Raw | ConvertFrom-Json
        $json.status = "ROLLED_BACK"
        $json.released_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        $json | ConvertTo-Json -Depth 4 | Set-Content $statePath -Force
        Write-Output "[MYX AI] Updated quarantine state file to ROLLED_BACK."
    } catch {
        Remove-Item $statePath -Force -ErrorAction SilentlyContinue
    }
}
