import { apiClient } from './apiClient';
import { DnsAnalysisResult, SslTlsAnalysisResult } from '../types/assessment.types';
import { INITIAL_DNS_RESULT, INITIAL_SSL_TLS_RESULT } from '../data/seedPreviewData';

export const analyzersService = {
  async analyzeSslTls(hostname: string, port = 443) {
    return apiClient.request<SslTlsAnalysisResult>(
      '/analyzers/ssl-tls/run',
      {
        method: 'POST',
        body: JSON.stringify({ hostname, port }),
      },
      () => ({
        ...INITIAL_SSL_TLS_RESULT,
        id: `tls-${Date.now()}`,
        target_hostname: hostname,
        port,
        analyzed_at: new Date().toISOString(),
      })
    );
  },

  async analyzeDns(domain: string) {
    return apiClient.request<DnsAnalysisResult>(
      '/analyzers/dns/run',
      {
        method: 'POST',
        body: JSON.stringify({ domain }),
      },
      () => ({
        ...INITIAL_DNS_RESULT,
        id: `dns-${Date.now()}`,
        domain,
        analyzed_at: new Date().toISOString(),
      })
    );
  },
};
