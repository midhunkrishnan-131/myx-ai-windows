import { apiClient } from './apiClient';
import { FindingStatus, VulnerabilityFinding } from '../types/findings.types';
import { INITIAL_FINDINGS } from '../data/seedPreviewData';

export const findingsService = {
  async listFindings() {
    return apiClient.request<VulnerabilityFinding[]>(
      '/findings',
      { method: 'GET' },
      () => INITIAL_FINDINGS
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
