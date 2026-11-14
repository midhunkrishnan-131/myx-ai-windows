import { apiClient } from './apiClient';
import { LinkGuardAnalysisResult } from '../types/assessment.types';
import { analyzeUrlWithLinkGuardLexical } from '../utils/securityLogic';

export const linkguardService = {
  async analyzeUrl(url: string, traceRedirects: boolean) {
    return apiClient.request<LinkGuardAnalysisResult>(
      '/intelligence/linkguard/analyze',
      {
        method: 'POST',
        body: JSON.stringify({ url, trace_redirects: traceRedirects }),
      },
      () => analyzeUrlWithLinkGuardLexical(url)
    );
  },
};
