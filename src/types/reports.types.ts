export type ReportWorkflowStatus = 'DRAFT' | 'IN_REVIEW' | 'APPROVED' | 'ARCHIVED';
export type SectionReviewStatus = 'AI_DRAFT_PENDING_REVIEW' | 'HUMAN_EDITED' | 'REVIEWER_APPROVED';

export type ExternalScannerType =
  | 'BURP_XML'
  | 'ZAP_JSON'
  | 'ZAP_XML'
  | 'NMAP_XML'
  | 'NESSUS_XML'
  | 'NIKTO';

export interface ReportSection {
  id: string;
  section_key:
    | 'executive_summary'
    | 'scope_and_methodology'
    | 'technical_risk_summary'
    | 'detailed_findings'
    | 'remediation_roadmap'
    | 'limitations_and_attestation';
  title: string;
  content_markdown: string;
  review_status: SectionReviewStatus;
  last_edited_by: string;
  reviewer_comment?: string;
}

export interface ReportVersionSnapshot {
  version_number: string;
  status: ReportWorkflowStatus;
  change_summary: string;
  is_ai_generated_draft: boolean;
  created_by_email: string;
  created_at: string;
}

export interface SecurityReport {
  id: string;
  report_code: string;
  title: string;
  project_name: string;
  organization_name: string;
  scope_targets: string[];
  assessment_date_window: string;
  status: ReportWorkflowStatus;
  current_version: string;
  created_by_email: string;
  assigned_reviewer_email: string;
  approved_by_email: string | null;
  approved_at: string | null;
  included_finding_codes: string[];
  external_import_sources: string[];
  sections: ReportSection[];
  versions: ReportVersionSnapshot[];
  created_at: string;
  updated_at: string;
}

export interface ExternalImportRecord {
  id: string;
  scanner_type: ExternalScannerType;
  original_filename: string;
  file_sha256: string;
  file_size_bytes: number;
  parse_status: 'PENDING' | 'PARSED' | 'FAILED';
  findings_imported_count: number;
  xxe_guard_verified: boolean;
  uploaded_by_email: string;
  created_at: string;
}
