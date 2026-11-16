/**
 * MYX AI Network Trust Intelligence — TypeScript Domain Types.
 * Brand: MYX AI by Midhun Krishnan ("Discover. Detect. Defend.")
 */

export type NetworkSeverityTier = 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL';
export type QuarantineActionType = 'NONE' | 'NOTIFY_USER' | 'SELECTIVE_RESTRICTION' | 'FULL_QUARANTINE';
export type ProfileApprovalStatus = 'APPROVED' | 'PENDING_REVIEW' | 'REJECTED';
export type ProfileType = 'PERSONAL' | 'ORGANIZATION';
export type ProtectionMode = 'BALANCED' | 'STRICT' | 'AUDIT_ONLY';

export interface FieldDiffRecord {
  field: string;
  baseline: any;
  observed: any;
  drift_category: 'BENIGN_ROAMING' | 'MINOR_DRIFT' | 'SUSPICIOUS_CHANGE' | 'CRITICAL_DOWNGRADE' | 'UNKNOWN_NETWORK' | 'SSID_MISMATCH' | 'NEW_ACCESS_POINT';
  severity: 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  explanation: string;
  risk_penalty: number;
}

export interface DetectedSignalRecord {
  rule_id: string;
  name: string;
  severity: string;
  penalty: number;
  evidence: Record<string, any>;
  explanation: string;
}

export interface LiveNetworkTelemetry {
  status: string;
  collected_at: string;
  adapter_name: string;
  ssid: string;
  bssid: string;
  signal_quality: number;
  auth_type: string;
  cipher: string;
  gateway_ip: string;
  gateway_mac: string;
  dns_servers: string[];
  dhcp_server?: string;
  captive_portal_detected: boolean;
  calculated_fingerprint: string;
  location_permission_required: boolean;
}

export interface NetworkProfileRecord {
  id: string;
  ssid: string;
  profile_type: ProfileType;
  status: ProfileApprovalStatus;
  baseline_fingerprint: string;
  baseline_auth: string;
  baseline_cipher: string;
  baseline_gateway_ip?: string;
  baseline_gateway_mac?: string;
  baseline_dns?: string[];
  baseline_bssids?: string[];
  approved_by?: string;
  approved_at?: string;
  created_at: string;
}

export interface NetworkRiskAssessmentResult {
  assessment_id?: string;
  risk_score: number;
  severity: NetworkSeverityTier;
  confidence: number;
  detected_signals: DetectedSignalRecord[];
  field_diffs: FieldDiffRecord[];
  evidence: Record<string, any>;
  explanation: string;
  recommended_action: string;
  quarantine_action: QuarantineActionType;
  policy_applied: string;
  assessed_at: string;
}

export interface NetworkQuarantineStatus {
  is_quarantined: boolean;
  active_session: {
    session_id: string;
    target_interface: string;
    trigger_reason: string;
    risk_score: number;
    expires_at: string;
    rules_applied: string[];
  } | null;
  is_elevated_admin: boolean;
}

export interface NetworkProtectionPolicyRecord {
  id?: string;
  name: string;
  mode: ProtectionMode;
  low_threshold: number;
  moderate_threshold: number;
  high_threshold: number;
  critical_threshold: number;
  allowed_dns: string[];
  auto_quarantine_enabled: boolean;
  watchdog_timeout_sec: number;
}

export interface AiNetworkExplanationResponse {
  mode: 'beginner' | 'technical';
  overview: string;
  what_happened?: string;
  real_world_impact?: string;
  recommended_steps?: string[];
  verified_facts?: Record<string, any>;
  technical_findings?: Array<{
    rule: string;
    title: string;
    penalty: number;
    evidence: any;
    explanation: string;
  }>;
  field_level_deltas?: FieldDiffRecord[];
  security_standards_relevance?: string[];
  remediation_instructions?: string[];
}
