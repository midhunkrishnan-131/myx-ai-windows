import { apiClient } from './apiClient';
import { AssessmentRun, NetworkPortResult } from '../types/assessment.types';

export interface NetworkAssessmentResponse {
  run: AssessmentRun;
  portResults: NetworkPortResult[];
  findings: any[];
  target: any;
  targets?: any[];
}

export const assessmentsService = {
  async listAssessments() {
    return apiClient.request<AssessmentRun[]>(
      '/assessments',
      { method: 'GET' },
      () => []
    );
  },

  async runWebsiteAssessment(targetId: string, targetUrl?: string, actorEmail?: string) {
    const canonicalTarget = (targetUrl || '').trim();
    return apiClient.request<{ run: AssessmentRun; findings: any[]; targets: any[] }>(
      '/assessments/website/run',
      {
        method: 'POST',
        body: JSON.stringify({
          target_id: targetId,
          targetUrl: canonicalTarget,
          target_value: canonicalTarget,
          target: canonicalTarget,
          actorEmail,
        }),
      }
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

  async downloadAssessmentPdf(assessmentId: string, filename?: string): Promise<void> {
    const fullUrl = `${apiClient.getBaseUrl()}/assessments/${assessmentId}/pdf`;
    const response = await fetch(fullUrl, {
      method: 'GET',
      credentials: 'include',
    });
    if (!response.ok) {
      throw new Error(`Failed to download report (HTTP ${response.status})`);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || `MYX-Security-Report-${assessmentId}.pdf`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },

  async compareAssessments(baseId: string, targetId: string) {
    return apiClient.request<{
      base_run: AssessmentRun;
      target_run: AssessmentRun;
      score_delta: number;
      remediated_controls: any[];
      new_regressions: any[];
      persistent_findings: any[];
      unchanged_passes: any[];
      summary: {
        remediated_count: number;
        regressions_count: number;
        persistent_count: number;
        score_improved: boolean;
      };
    }>(`/assessments/compare?base_id=${encodeURIComponent(baseId)}&target_id=${encodeURIComponent(targetId)}`);
  },

  async getAssessmentHistory(params: {
    limit?: number;
    offset?: number;
    search?: string;
    scoreMin?: number;
    scoreMax?: number;
    module?: string;
  } = {}) {
    const q = new URLSearchParams();
    if (params.limit) q.set('limit', String(params.limit));
    if (params.offset) q.set('offset', String(params.offset));
    if (params.search) q.set('search', params.search);
    if (params.scoreMin !== undefined) q.set('score_min', String(params.scoreMin));
    if (params.scoreMax !== undefined) q.set('score_max', String(params.scoreMax));
    if (params.module) q.set('module', params.module);
    return apiClient.request<{ assessments: AssessmentRun[]; total: number; limit: number; offset: number }>(
      `/assessments/history?${q.toString()}`
    );
  },

  async runNetworkAssessment(
    targetId: string,
    profile: string = 'WINDOWS_ENTERPRISE',
    customPorts?: string,
    actorEmail?: string
  ) {
    return apiClient.request<NetworkAssessmentResponse>(
      '/assessments/network/run',
      {
        method: 'POST',
        body: JSON.stringify({ target_id: targetId, profile, customPorts, actorEmail }),
      },
      () => ({
        run: {
          id: `asm-net-${Date.now()}`,
          organization_id: 'org-myx-enterprise-01',
          target_id: targetId,
          target_display: 'Network Endpoint',
          target_value: 'Network Endpoint',
          module_type: 'NETWORK' as const,
          profile_name:
            profile === 'QUICK_WEB'
              ? 'Quick Web & Infra TCP Audit'
              : profile === 'CUSTOM_BOUNDED'
              ? 'Custom Bounded TCP Audit'
              : 'Windows Enterprise Port Discovery',
          status: 'COMPLETED' as const,
          started_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          initiated_by_email: actorEmail || 'midhun.krishnan@myx-security.io',
          risk_score: 90,
          summary: { total_checks: 0, passed: 0, warnings: 0, failed: 0, requires_elevation: 0 },
          results: [],
          findings_count: 0,
          is_demo_preview: false,
        },
        portResults: [],
        findings: [],
        target: null,
      })
    );
  },

  async scanNetworkTarget(
    targetHost: string,
    profile: string = 'WINDOWS_ENTERPRISE',
    customPorts?: string,
    actorEmail?: string
  ) {
    return apiClient.request<NetworkAssessmentResponse>(
      '/assessments/network/scan',
      {
        method: 'POST',
        body: JSON.stringify({ targetHost, profile, customPorts, actorEmail }),
      },
      () => ({
        run: {
          id: `asm-net-${Date.now()}`,
          organization_id: 'org-myx-enterprise-01',
          target_id: 'tgt-quick',
          target_display: targetHost,
          target_value: targetHost,
          module_type: 'NETWORK' as const,
          profile_name:
            profile === 'QUICK_WEB'
              ? 'Quick Web & Infra TCP Audit'
              : profile === 'CUSTOM_BOUNDED'
              ? 'Custom Bounded TCP Audit'
              : 'Windows Enterprise Port Discovery',
          status: 'COMPLETED' as const,
          started_at: new Date().toISOString(),
          completed_at: new Date().toISOString(),
          initiated_by_email: actorEmail || 'midhun.krishnan@myx-security.io',
          risk_score: 90,
          summary: { total_checks: 0, passed: 0, warnings: 0, failed: 0, requires_elevation: 0 },
          results: [],
          findings_count: 0,
          is_demo_preview: false,
        },
        portResults: [],
        findings: [],
        target: null,
      })
    );
  },
};
