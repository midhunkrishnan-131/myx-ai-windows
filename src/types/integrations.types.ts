export type IntegrationProviderCode =
  | 'GEMINI'
  | 'RESEND'
  | 'POSTGRES_EXTERNAL'
  | 'GOOGLE_SAFE_BROWSING'
  | 'VIRUSTOTAL'
  | 'URLHAUS'
  | 'SCANNER_PARSERS';

export type IntegrationOperationalState =
  | 'Connected'
  | 'Disconnected'
  | 'Misconfigured'
  | 'Unavailable';

export interface IntegrationConfigRecord {
  provider: IntegrationProviderCode;
  display_name: string;
  category: 'AI & Embeddings' | 'Database & Vector Store' | 'Threat Intelligence' | 'Transactional Email' | 'Import Engine';
  description: string;
  status: IntegrationOperationalState;
  has_configured_secret: boolean;
  masked_secret_suffix: string | null;
  non_sensitive_config: Record<string, string>;
  last_tested_at: string | null;
  latency_ms: number | null;
  last_error_message: string | null;
  env_var_name: string;
}
