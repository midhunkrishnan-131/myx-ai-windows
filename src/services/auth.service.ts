import { apiClient } from './apiClient';
import { TotpConfirmResponse, TotpSetupResponse, UserProfile, UserSession } from '../types/auth.types';
import { INITIAL_CURRENT_USER, INITIAL_USER_SESSIONS } from '../data/seedPreviewData';

export const authService = {
  async getCurrentUser() {
    return apiClient.request<UserProfile>('/auth/me', { method: 'GET' }, () => INITIAL_CURRENT_USER);
  },

  async getSessions() {
    return apiClient.request<UserSession[]>('/auth/sessions', { method: 'GET' }, () => INITIAL_USER_SESSIONS);
  },

  async initiateTotpSetup(email: string) {
    return apiClient.request<TotpSetupResponse>(
      '/auth/2fa/setup',
      { method: 'POST' },
      () => {
        const secret = 'JBSWY3DPEHPK3PXP8M2Q4R7V9K3L5N8B';
        const grouped = 'JBSW Y3DP EHPK 3PXP 8M2Q 4R7V 9K3L 5N8B';
        const uri = `otpauth://totp/MYX%20AI:${encodeURIComponent(email)}?secret=${secret}&issuer=MYX%20AI&algorithm=SHA1&digits=6&period=30`;
        const svgQr = `data:image/svg+xml;utf8,${encodeURIComponent(
          `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 180 180" fill="none">
            <rect width="180" height="180" rx="8" fill="#F5F7FA"/>
            <rect x="16" y="16" width="44" height="44" stroke="#080A0D" stroke-width="6" fill="none"/>
            <rect x="28" y="28" width="20" height="20" fill="#080A0D"/>
            <rect x="120" y="16" width="44" height="44" stroke="#080A0D" stroke-width="6" fill="none"/>
            <rect x="132" y="28" width="20" height="20" fill="#080A0D"/>
            <rect x="16" y="120" width="44" height="44" stroke="#080A0D" stroke-width="6" fill="none"/>
            <rect x="28" y="132" width="20" height="20" fill="#080A0D"/>
            <path d="M72 24h12v12H72zM96 24h12v24H96zM72 48h12v24H72zM84 72h24v12H84zM60 84h24v12H60zM108 84h12v24h-12zM132 72h24v12h-24zM72 108h24v12H72zM96 120h24v24H96zM132 120h12v36h-12zM72 144h12v12H72z" fill="#080A0D"/>
          </svg>`
        )}`;
        return {
          otpauth_uri: uri,
          qr_code_svg_data_uri: svgQr,
          manual_secret_grouped: grouped,
          issuer: 'MYX AI',
          account_email: email,
          algorithm: 'SHA1',
          digits: 6,
          period: 30,
        };
      }
    );
  },

  async confirmTotpSetup(totpCode: string) {
    return apiClient.request<TotpConfirmResponse>(
      '/auth/2fa/confirm',
      {
        method: 'POST',
        body: JSON.stringify({ code: totpCode }),
      },
      () => ({
        is_enabled: true,
        verified_at: new Date().toISOString(),
        recovery_codes: [
          'MYX-8F3A-9C2D',
          'MYX-4B7E-1A6F',
          'MYX-2D9C-5E8A',
          'MYX-7C1F-3B4D',
          'MYX-9E6A-2F1C',
          'MYX-5A2B-8D7E',
          'MYX-3F8C-6E1A',
          'MYX-1D4E-9A3B',
          'MYX-6B5F-4C8D',
          'MYX-0A9E-7B2C',
        ],
      })
    );
  },
};
