import { apiClient } from './apiClient';
import { FindingStatus, VulnerabilityFinding } from '../types/findings.types';

export const findingsService = {
  async listFindings() {
    return apiClient.request<VulnerabilityFinding[]>(
      '/findings',
      { method: 'GET' },
      () => []
    );
  },

  async updateFindingStatus(findingId: string, status: FindingStatus) {
    return apiClient.request<{ id: string; status: FindingStatus }>(
      `/findings/${findingId}/status`,
      {
        method: 'POST',
        body: JSON.stringify({ status }),
      },
      () => ({ id: findingId, status })
    );
  },
};
