import { apiClient } from './apiClient';
import { AuthorizedTarget } from '../types/assessment.types';
import { INITIAL_AUTHORIZED_TARGETS } from '../data/seedPreviewData';

export const targetsService = {
  async listTargets() {
    return apiClient.request<AuthorizedTarget[]>(
      '/targets',
      { method: 'GET' },
      () => INITIAL_AUTHORIZED_TARGETS
    );
  },

  async verifyTargetOwnership(targetId: string) {
    return apiClient.request<{ verified: boolean; verified_at: string }>(
      `/targets/${targetId}/verify`,
      { method: 'POST' },
      () => ({
        verified: true,
        verified_at: new Date().toISOString(),
      })
    );
  },
};
