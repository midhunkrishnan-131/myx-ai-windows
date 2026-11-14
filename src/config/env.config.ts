export interface EnvConfig {
  API_BASE_URL: string;
  EXTERNAL_FASTAPI_URL: string;
  API_V1_PREFIX: string;
  APP_ENV: 'development' | 'staging' | 'production';
  DEFAULT_TIMEOUT_MS: number;
}

const rawBaseUrl =
  (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_BASE_URL) ||
  (typeof window !== 'undefined' && (window.location.port === '5500' || window.location.port === '5501')
    ? 'http://localhost:3000'
    : '');

export const ENV_CONFIG: EnvConfig = {
  API_BASE_URL: rawBaseUrl.replace(/\/+$/, ''),
  EXTERNAL_FASTAPI_URL: 'http://127.0.0.1:8000',
  API_V1_PREFIX: '/api/v1',
  APP_ENV:
    ((typeof import.meta !== 'undefined' && import.meta.env?.VITE_APP_ENV) as
      | 'development'
      | 'staging'
      | 'production') || 'development',
  DEFAULT_TIMEOUT_MS: 10000,
};

