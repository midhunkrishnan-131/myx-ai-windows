export type GeminiModelTier = 'FAST' | 'PRIMARY' | 'ADVANCED';

export interface RagCitation {
  chunk_id: string;
  document_title: string;
  source_type: 'OWASP_GUIDE' | 'WINDOWS_BASELINE' | 'ORG_POLICY' | 'ASSESSMENT_SUMMARY';
  section_heading: string;
  reference_code: string;
  similarity_score: number;
}

export interface StructuredAiSecurityResponse {
  verified_facts: string[];
  ai_risk_interpretation: string;
  recommended_remediation: string;
  assumptions_and_limitations: string;
  referenced_finding_codes: string[];
  rag_citations: RagCitation[];
  confidence_note: string;
}

export interface AiAnalystMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  structured_response?: StructuredAiSecurityResponse;
  model_tier: GeminiModelTier;
  model_name: string;
  latency_ms: number;
  created_at: string;
}

export interface AiConversationSession {
  id: string;
  title: string;
  attached_finding_codes: string[];
  attached_assessment_ids: string[];
  attached_windows_hosts: string[];
  updated_at: string;
  messages: AiAnalystMessage[];
}

export interface RagDocumentRecord {
  id: string;
  title: string;
  source_type: 'OWASP_GUIDE' | 'WINDOWS_BASELINE' | 'ORG_POLICY' | 'ASSESSMENT_SUMMARY';
  source_reference: string;
  is_global_reference: boolean;
  chunk_count: number;
  created_at: string;
}
