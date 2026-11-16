import { apiClient } from './apiClient';
import {
  LiveNetworkTelemetry,
  NetworkProfileRecord,
  NetworkRiskAssessmentResult,
  NetworkQuarantineStatus,
  NetworkProtectionPolicyRecord,
  AiNetworkExplanationResponse,
} from '../types/network_trust.types';

export const networkTrustService = {
  async getLiveTelemetry() {
    return apiClient.request<LiveNetworkTelemetry>(
      '/network-trust/live',
      { method: 'GET' },
      () => ({
        status: 'LIVE_OBSERVED',
        collected_at: new Date().toISOString(),
        adapter_name: 'Wi-Fi',
        ssid: 'MYX-Enterprise-Secure',
        bssid: '00:14:22:01:23:45',
        signal_quality: 92,
        auth_type: 'WPA3-Enterprise',
        cipher: 'GCMP-256',
        gateway_ip: '10.0.0.1',
        gateway_mac: '00:14:22:FE:DC:BA',
        dns_servers: ['10.0.0.53', '1.1.1.1'],
        dhcp_server: '10.0.0.1',
        captive_portal_detected: false,
        calculated_fingerprint: 'a8f94c1b2e537d890fe34521bcde45aa8910',
        location_permission_required: false,
      })
    );
  },

  async getProfiles() {
    return apiClient.request<{ count: number; profiles: NetworkProfileRecord[] }>(
      '/network-trust/profiles',
      { method: 'GET' },
      () => ({
        count: 1,
        profiles: [
          {
            id: 'prof-corp-01',
            ssid: 'MYX-Enterprise-Secure',
            profile_type: 'ORGANIZATION',
            status: 'APPROVED',
            baseline_fingerprint: 'a8f94c1b2e537d890fe34521bcde45aa8910',
            baseline_auth: 'WPA3-Enterprise',
            baseline_cipher: 'GCMP-256',
            baseline_gateway_ip: '10.0.0.1',
            baseline_gateway_mac: '00:14:22:FE:DC:BA',
            baseline_dns: ['10.0.0.53', '1.1.1.1'],
            baseline_bssids: ['00:14:22:01:23:45', '00:14:22:01:23:46'],
            approved_by: 'Midhun Krishnan',
            approved_at: new Date().toISOString(),
            created_at: new Date().toISOString(),
          },
        ],
      })
    );
  },

  async createProfile(data: {
    ssid: string;
    profile_type?: 'PERSONAL' | 'ORGANIZATION';
    auth_type: string;
    cipher: string;
    gateway_ip?: string;
    gateway_mac?: string;
    dns_servers?: string[];
    baseline_bssids?: string[];
  }) {
    return apiClient.request<{
      status: string;
      profile_id: string;
      ssid: string;
      approval_status: string;
      baseline_fingerprint: string;
    }>(
      '/network-trust/profiles',
      {
        method: 'POST',
        body: JSON.stringify(data),
      },
      () => ({
        status: 'CREATED',
        profile_id: `prof-${Date.now()}`,
        ssid: data.ssid,
        approval_status: 'APPROVED',
        baseline_fingerprint: `fp-${Date.now()}`,
      })
    );
  },

  async approveProfile(profileId: string) {
    return apiClient.request<{ status: string; profile_id: string }>(
      `/network-trust/profiles/${profileId}/approve`,
      { method: 'POST' },
      () => ({
        status: 'APPROVED',
        profile_id: profileId,
      })
    );
  },

  async evaluateRisk(observation: {
    ssid: string;
    bssid?: string;
    auth_type: string;
    cipher: string;
    signal_quality?: number;
    gateway_ip?: string;
    gateway_mac?: string;
    dns_servers?: string[];
    captive_portal_detected?: boolean;
    profile_id?: string;
  }) {
    return apiClient.request<NetworkRiskAssessmentResult>(
      '/network-trust/evaluate',
      {
        method: 'POST',
        body: JSON.stringify(observation),
      },
      () => ({
        assessment_id: `eval-${Date.now()}`,
        risk_score: 15,
        severity: 'LOW',
        confidence: 95,
        detected_signals: [],
        field_diffs: [],
        evidence: observation,
        explanation: `Network '${observation.ssid}' matches approved security baseline. No active downgrade, rogue AP, or ARP spoofing signals detected.`,
        recommended_action: 'Network characteristics verified against baseline. Continue passive background monitoring.',
        quarantine_action: 'NONE',
        policy_applied: 'Balanced Protection Mode Default',
        assessed_at: new Date().toISOString(),
      })
    );
  },

  async applyQuarantine(params: {
    host_id?: string;
    reason: string;
    risk_score: number;
    target_interface?: string;
    pinned_dns_ips?: string[];
    timeout_seconds?: number;
  }) {
    return apiClient.request<{
      session_id: string;
      status: string;
      host_id: string;
      target_interface: string;
      rules_applied: string[];
      expires_at: string;
      timeout_seconds: number;
      message: string;
    }>(
      '/network-trust/quarantine/apply',
      {
        method: 'POST',
        body: JSON.stringify(params),
      },
      () => ({
        session_id: `nti-q-${Date.now()}`,
        status: 'ACTIVE',
        host_id: params.host_id || 'LOCAL-WINDOWS-HOST',
        target_interface: params.target_interface || 'Wi-Fi',
        rules_applied: [
          'MYX_AI_NTI_BLOCK_OUT_WIFI',
          'MYX_AI_NTI_ALLOW_OUT_DNS_PINNED',
          'MYX_AI_NTI_ALLOW_OUT_DHCP',
          'MYX_AI_NTI_ALLOW_LO',
        ],
        expires_at: new Date(Date.now() + (params.timeout_seconds || 900) * 1000).toISOString(),
        timeout_seconds: params.timeout_seconds || 900,
        message: 'Scoped quarantine rules successfully applied to wireless interface via Windows Agent.',
      })
    );
  },

  async releaseQuarantine(sessionId?: string) {
    return apiClient.request<{
      status: string;
      released_sessions_count: number;
      released_at: string;
      message: string;
    }>(
      '/network-trust/quarantine/release',
      {
        method: 'POST',
        body: JSON.stringify({ session_id: sessionId }),
      },
      () => ({
        status: 'ROLLED_BACK',
        released_sessions_count: 1,
        released_at: new Date().toISOString(),
        message: 'Quarantine rules rolled back cleanly. Wireless network access restored.',
      })
    );
  },

  async getQuarantineStatus() {
    return apiClient.request<NetworkQuarantineStatus>(
      '/network-trust/quarantine/status',
      { method: 'GET' },
      () => ({
        is_quarantined: false,
        active_session: null,
        is_elevated_admin: true,
      })
    );
  },

  async getPolicies() {
    return apiClient.request<NetworkProtectionPolicyRecord>(
      '/network-trust/policies',
      { method: 'GET' },
      () => ({
        id: 'pol-default',
        name: 'MYX Balanced Protection Mode Default',
        mode: 'BALANCED',
        low_threshold: 24,
        moderate_threshold: 49,
        high_threshold: 74,
        critical_threshold: 75,
        allowed_dns: ['1.1.1.1', '9.9.9.9', '8.8.8.8'],
        auto_quarantine_enabled: true,
        watchdog_timeout_sec: 900,
      })
    );
  },

  async updatePolicy(policy: Partial<NetworkProtectionPolicyRecord>) {
    return apiClient.request<{ status: string; policy_id?: string }>(
      '/network-trust/policies',
      {
        method: 'PUT',
        body: JSON.stringify(policy),
      },
      () => ({
        status: 'UPDATED',
      })
    );
  },

  async getHistory(limit: number = 20) {
    return apiClient.request<{ count: number; history: NetworkRiskAssessmentResult[] }>(
      `/network-trust/history?limit=${limit}`,
      { method: 'GET' },
      () => ({
        count: 0,
        history: [],
      })
    );
  },

  async getAiExplanation(riskAssessment: NetworkRiskAssessmentResult, mode: 'beginner' | 'technical' = 'beginner') {
    return apiClient.request<AiNetworkExplanationResponse>(
      '/network-trust/ai/explain',
      {
        method: 'POST',
        body: JSON.stringify({ risk_assessment: riskAssessment, mode }),
      },
      () => ({
        mode,
        overview: `Network Security Briefing for '${riskAssessment.evidence?.ssid || 'Network'}' — Risk: ${riskAssessment.severity} (${riskAssessment.risk_score}/100)`,
        what_happened: `MYX AI analyzed your current Wi-Fi connection characteristics against approved baseline.`,
        real_world_impact: riskAssessment.risk_score >= 50
          ? 'Potential risk of traffic tampering or redirection on unverified network.'
          : 'Standard encrypted traffic is operating under normal parameters.',
        recommended_steps: [
          'Verify network authenticity with facility or IT management',
          'Ensure Windows Defender Firewall remains enabled',
        ],
        verified_facts: riskAssessment.evidence || {},
      })
    );
  },
};
