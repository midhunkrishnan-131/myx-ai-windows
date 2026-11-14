import { ConfidenceLevel, SeverityLevel } from './assessment.types';

export type FindingStatus =
  | 'Open'
  | 'In Progress'
  | 'Fixed'
  | 'Accepted Risk'
  | 'False Positive'
  | 'Reopened';

export type EvidenceType =
  | 'HTTP_TRACE'
  | 'TLS_CERT'
  | 'DNS_RECORD'
  | 'PORT_BANNER'
  | 'WINDOWS_REGISTRY'
  | 'WINDOWS_CMDLET'
  | 'SCREENSHOT'
  | 'SCANNER_RAW';

export interface FindingEvidenceItem {
  id: string;
  evidence_type: EvidenceType;
  title: string;
  content_text: string;
  sha256_hash: string;
  uploaded_by_email: string;
  created_at: string;
}

export interface FindingCommentItem {
  id: string;
  author_email: string;
  author_role: string;
  comment_body: string;
  is_retest_note: boolean;
  retest_outcome: 'PASSED' | 'FAILED' | 'PARTIAL' | null;
  created_at: string;
}

export interface FindingAuditItem {
  id: string;
  actor_email: string;
  action: string;
  previous_value: string | null;
  new_value: string | null;
  timestamp: string;
}

export interface VulnerabilityFinding {
  id: string;
  finding_code: string;
  organization_id: string;
  assessment_id: string | null;
  title: string;
  description: string;
  affected_asset: string;
  affected_endpoint: string;
  severity: SeverityLevel;
  confidence: ConfidenceLevel;
  status: FindingStatus;
  cvss_version: '3.1';
  cvss_score: number | null;
  cvss_vector: string | null;
  cve_ids: string[];
  cwe_id: string | null;
  owasp_category: string | null;
  detection_source: string;
  remediation_guidance: string;
  assigned_analyst_email: string | null;
  first_detected_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  is_demo_preview: boolean;
  evidence: FindingEvidenceItem[];
  comments: FindingCommentItem[];
  audit_trail: FindingAuditItem[];
}
