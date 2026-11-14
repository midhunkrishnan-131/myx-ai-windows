import { apiClient } from './apiClient';
import { AssessmentRun, NetworkPortResult } from '../types/assessment.types';
import { INITIAL_ASSESSMENT_RUNS, INITIAL_NETWORK_PORT_RESULTS } from '../data/seedPreviewData';

export const assessmentsService = {
  async listAssessments() {
    return apiClient.request<AssessmentRun[]>(
      '/assessments',
      { method: 'GET' },
      () => INITIAL_ASSESSMENT_RUNS
    );
  },

  async runWebsiteAssessment(targetId: string) {
    return apiClient.request<AssessmentRun>(
      '/assessments/website/run',
      {
        method: 'POST',
        body: JSON.stringify({ target_id: targetId }),
      },
      () => INITIAL_ASSESSMENT_RUNS[0]
    );
  },

  async scanWebsiteUrl(targetUrl: string, actorEmail?: string) {
    return apiClient.request<{ run: AssessmentRun; findings: any[]; targets: any[] }>(
      '/assessments/scan-website',
      {
        method: 'POST',
        body: JSON.stringify({ targetUrl, actorEmail }),
      }
    );
  },

  async runNetworkAssessment(targetId: string, profile: string) {
    return apiClient.request<NetworkPortResult[]>(
      '/assessments/network/run',
      {
        method: 'POST',
        body: JSON.stringify({ target_id: targetId, profile }),
      },
      () => INITIAL_NETWORK_PORT_RESULTS
    );
  },
};
