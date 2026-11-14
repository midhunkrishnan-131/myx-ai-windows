export type UserRole = 'ADMIN' | 'SECURITY_ANALYST' | 'VIEWER';

export interface UserProfile {
  id: string;
  email: string;
  full_name: string;
  job_title: string;
  role: UserRole;
  organization_id: string;
  organization_name: string;
  organization_slug: string;
  is_active: boolean;
  is_email_verified: boolean;
  totp_enabled: boolean;
  last_login_at: string;
  created_at: string;
}

export interface UserSession {
  id: string;
  user_id: string;
  organization_id: string;
  ip_address: string;
  user_agent: string;
  device_label: string;
  is_2fa_verified: boolean;
  is_current: boolean;
  created_at: string;
  last_active_at: string;
  expires_at: string;
  revoked_at: string | null;
}

export interface TotpSetupResponse {
  otpauth_uri: string;
  qr_code_svg_data_uri: string;
  manual_secret_grouped: string;
  issuer: string;
  account_email: string;
  algorithm: 'SHA1';
  digits: 6;
  period: 30;
}

export interface TotpConfirmResponse {
  is_enabled: boolean;
  verified_at: string;
  recovery_codes: string[];
}

export interface SecurityAuditEvent {
  id: string;
  organization_id: string;
  actor_user_id: string;
  actor_email: string;
  actor_role: UserRole;
  event_category:
    | 'AUTH'
    | '2FA'
    | 'TARGET_AUTH'
    | 'ASSESSMENT'
    | 'AGENT'
    | 'FINDING'
    | 'REPORT'
    | 'INTEGRATION'
    | 'RBAC';
  action: string;
  resource_type: string;
  resource_id: string;
  ip_address: string;
  user_agent: string;
  metadata_json: Record<string, unknown>;
  created_at: string;
}
