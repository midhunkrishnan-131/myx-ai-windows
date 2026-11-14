export type TargetType = 'DOMAIN' | 'URL' | 'IPV4' | 'CIDR' | 'WINDOWS_HOST';
export type TargetEnvironment = 'PRODUCTION' | 'STAGING' | 'LAB';
export type VerificationStatus = 'PENDING' | 'VERIFIED' | 'REVOKED' | 'EXPIRED';
export type VerificationMethod = 'DNS_TXT' | 'HTTP_FILE' | 'ADMIN_LAB_APPROVAL';

export interface AuthorizedTarget {
  id: string;
  organization_id: string;
  target_type: TargetType;
  target_value: string;
  display_name: string;
  environment: TargetEnvironment;
  verification_status: VerificationStatus;
  verification_method: VerificationMethod;
  verification_token: string;
  verified_at: string | null;
  expires_at: string | null;
  allowlisted: boolean;
  attestation_notes?: string;
  created_by_email: string;
  created_at: string;
}

export type AssessmentModuleType =
  | 'WEBSITE'
  | 'NETWORK'
  | 'WIFI'
  | 'WINDOWS'
  | 'LINKGUARD'
  | 'SSL_TLS'
  | 'DNS';

export type AssessmentRunStatus =
  | 'QUEUED'
  | 'RUNNING'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELLED';

export type CheckOutcomeStatus =
  | 'PASS'
  | 'WARNING'
  | 'FAIL'
  | 'INFO'
  | 'UNSUPPORTED'
  | 'REQUIRES_ELEVATION';

export type SeverityLevel =
  | 'Critical'
  | 'High'
  | 'Medium'
  | 'Low'
  | 'Informational';

export type ConfidenceLevel = 'Confirmed' | 'High' | 'Medium' | 'Low';

export interface AssessmentCheckResult {
  id: string;
  check_code: string;
  check_title: string;
  category: string;
  status: CheckOutcomeStatus;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  raw_evidence: string;
  remediation_text: string;
}

export interface AssessmentRun {
  id: string;
  organization_id: string;
  target_id: string | null;
  target_display: string;
  module_type: AssessmentModuleType;
  status: AssessmentRunStatus;
  initiated_by_email: string;
  profile_name: string;
  risk_score: number;
  started_at: string;
  completed_at: string | null;
  is_demo_preview: boolean;
  summary: {
    total_checks: number;
    passed: number;
    warnings: number;
    failed: number;
    requires_elevation: number;
  };
  results: AssessmentCheckResult[];
}

export interface NetworkPortResult {
  port: number;
  protocol: 'TCP';
  service_name: string;
  state: 'open' | 'closed' | 'filtered';
  banner: string | null;
  risk_level: SeverityLevel;
  change_since_last_scan: 'unchanged' | 'newly_opened' | 'newly_closed';
  notes: string;
}

export type LinkGuardVerdict =
  | 'Known Malicious Match'
  | 'Suspicious'
  | 'No Known Threat Detected'
  | 'Unknown or Insufficient Evidence';

export interface LinkGuardAnalysisResult {
  id: string;
  input_url: string;
  normalized_url: string;
  hostname: string;
  verdict: LinkGuardVerdict;
  risk_score: number;
  analyzed_at: string;
  is_demo_preview: boolean;
  lexical_signals: {
    scheme: string;
    has_authority_at_trick: boolean;
    is_raw_ip: boolean;
    subdomain_count: number;
    is_punycode_idn: boolean;
    decoded_idn_hostname: string | null;
    confusable_homograph_detected: boolean;
    lookalike_brand_target: string | null;
    suspicious_extension: string | null;
    open_redirect_param: string | null;
    url_shortener: boolean;
    ssrf_blocked: boolean;
    ssrf_block_reason: string | null;
  };
  redirect_chain: Array<{
    hop: number;
    url: string;
    status_code: number;
    resolved_ip: string;
    latency_ms: number;
    https_downgrade: boolean;
  }>;
  threat_intel_sources: Array<{
    provider: 'Google Safe Browsing v4' | 'VirusTotal v3' | 'abuse.ch URLhaus';
    status: 'Clean' | 'Malicious Match' | 'Suspicious' | 'Not Configured / Skipped';
    details: string;
  }>;
  ai_explanation: {
    verified_facts: string[];
    ai_risk_interpretation: string;
    recommended_remediation: string;
    assumptions_and_limitations: string;
  };
}

export interface SslTlsAnalysisResult {
  id: string;
  target_hostname: string;
  port: number;
  analyzed_at: string;
  is_demo_preview: boolean;
  certificate: {
    subject_cn: string;
    sans: string[];
    hostname_matches: boolean;
    issuer_org: string;
    issuer_cn: string;
    serial_number: string;
    signature_algorithm: string;
    public_key_algorithm: string;
    public_key_bits: number;
    not_before: string;
    not_after: string;
    days_until_expiry: number;
    is_self_signed: boolean;
    chain_complete: boolean;
  };
  protocols: Array<{
    version: 'SSLv3' | 'TLSv1.0' | 'TLSv1.1' | 'TLSv1.2' | 'TLSv1.3';
    supported: boolean;
    status: 'PASS' | 'WARNING' | 'FAIL';
    notes: string;
  }>;
  negotiated_cipher: {
    name: string;
    tls_version: string;
    kx_algorithm: string;
    auth_algorithm: string;
    enc_algorithm: string;
    weak_cipher_detected: boolean;
  };
}

export interface DnsAnalysisResult {
  id: string;
  domain: string;
  analyzed_at: string;
  is_demo_preview: boolean;
  records: {
    A: string[];
    AAAA: string[];
    MX: Array<{ priority: number; exchange: string }>;
    NS: string[];
    TXT: string[];
    CNAME: string[];
    SOA: string | null;
  };
  spf: {
    present: boolean;
    raw_record: string | null;
    multiple_records_violation: boolean;
    dns_lookup_count: number;
    exceeds_10_lookup_limit: boolean;
    all_qualifier: '-all' | '~all' | '?all' | '+all' | 'missing';
    status: 'PASS' | 'WARNING' | 'FAIL';
    explanation: string;
  };
  dmarc: {
    present: boolean;
    raw_record: string | null;
    policy: 'reject' | 'quarantine' | 'none' | 'missing';
    subdomain_policy: string | null;
    pct: number;
    rua: string[];
    ruf: string[];
    adkim: 'r' | 's';
    aspf: 'r' | 's';
    status: 'PASS' | 'WARNING' | 'FAIL';
    explanation: string;
  };
  dnssec: {
    signed: boolean;
    dnskey_present: boolean;
    ds_present: boolean;
    status: 'PASS' | 'WARNING';
    explanation: string;
  };
}
