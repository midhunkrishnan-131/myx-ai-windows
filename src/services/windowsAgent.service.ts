import { apiClient } from './apiClient';
import { WifiNetworkAuditEntry, WindowsAgentRecord } from '../types/windows.types';

export const windowsAgentService = {
  async listAgents() {
    return apiClient.request<WindowsAgentRecord[]>(
      '/windows/agents',
      { method: 'GET' },
      () => []
    );
  },

  async generateEnrollmentToken(intendedHostname: string, displayName: string) {
    return apiClient.request<{
      enrollment_token: string;
      expires_in_minutes: number;
      cli_command: string;
    }>(
      '/windows/agents/enroll-token',
      {
        method: 'POST',
        body: JSON.stringify({ intended_hostname: intendedHostname, display_name: displayName }),
      },
      () => {
        const suffix = Math.random().toString(36).substring(2, 6).toUpperCase();
        const token = `MYX-ENR-2026-${intendedHostname.replace(/[^A-Z0-9]/gi, '').slice(0, 6).toUpperCase()}-${suffix}`;
        return {
          enrollment_token: token,
          expires_in_minutes: 15,
          cli_command: `python myx_windows_agent.py enroll --server http://127.0.0.1:8000 --token ${token}`,
        };
      }
    );
  },

  async revokeAgent(agentId: string) {
    return apiClient.request<{ revoked: boolean; revoked_at: string }>(
      `/windows/agents/${agentId}/revoke`,
      { method: 'POST' },
      () => ({
        revoked: true,
        revoked_at: new Date().toISOString(),
      })
    );
  },

  async getWifiAuditRuns() {
    return apiClient.request<WifiNetworkAuditEntry[]>(
      '/auditors/wifi/runs',
      { method: 'GET' },
      () => []
    );
  },

  async scanWifiNetworks() {
    return apiClient.request<{ ok: boolean; wifiNetworks: WifiNetworkAuditEntry[]; scannedAt: string }>(
      '/auditors/wifi/scan',
      { method: 'POST' },
      () => ({ ok: true, wifiNetworks: [], scannedAt: new Date().toISOString() })
    );
  },
};
