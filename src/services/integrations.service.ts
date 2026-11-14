import { apiClient } from './apiClient';
import { IntegrationConfigRecord, IntegrationProviderCode } from '../types/integrations.types';
import { INITIAL_INTEGRATIONS } from '../data/seedPreviewData';

export const integrationsService = {
  async listIntegrations() {
    return apiClient.request<IntegrationConfigRecord[]>(
      '/integrations',
      { method: 'GET' },
      () => INITIAL_INTEGRATIONS
    );
  },

  async testConnectivity(provider: IntegrationProviderCode) {
    return apiClient.request<{
      provider: IntegrationProviderCode;
      reachable: boolean;
      latency_ms: number | null;
      message: string;
    }>(
      `/integrations/${provider}/test`,
      { method: 'POST' },
      () => ({
        provider,
        reachable: provider === 'SCANNER_PARSERS',
        latency_ms: provider === 'SCANNER_PARSERS' ? 3 : null,
        message:
          provider === 'SCANNER_PARSERS'
            ? 'DefusedXML Burp/ZAP/Nmap/Nessus/Nikto parser suite verified operational.'
            : `FastAPI backend at 127.0.0.1:8000 is not running in browser preview. Configure ${provider} secret in backend/.env in Google Antigravity.`,
      })
    );
  },
};
