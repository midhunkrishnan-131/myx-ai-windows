import { ENV_CONFIG } from '../config/env.config';

export type BackendTargetMode = 'INTEGRATED_BACKEND' | 'EXTERNAL_FASTAPI' | 'OFFLINE_SANDBOX';

export interface ApiEnvelope<T> {
  data: T;
  meta: {
    backend_connected: boolean;
    is_demo_preview: boolean;
    timestamp: string;
    endpoint: string;
  };
}

class CentralizedApiClient {
  private csrfToken: string = 'myx-csrf-session-token-init';
  private backendReachable: boolean = false;
  private lastHealthCheckAt: string | null = null;
  private lastLatencyMs: number | null = null;
  private targetMode: BackendTargetMode = 'INTEGRATED_BACKEND';

  public setCsrfToken(token: string) {
    this.csrfToken = token;
  }

  public getCsrfToken(): string {
    return this.csrfToken;
  }

  public isBackendConnected(): boolean {
    return this.backendReachable;
  }

  public getLastHealthCheckAt(): string | null {
    return this.lastHealthCheckAt;
  }

  public getLastLatencyMs(): number | null {
    return this.lastLatencyMs;
  }

  public getTargetMode(): BackendTargetMode {
    return this.targetMode;
  }

  public setTargetMode(mode: BackendTargetMode) {
    this.targetMode = mode;
    if (mode === 'OFFLINE_SANDBOX') {
      this.backendReachable = false;
      this.lastLatencyMs = null;
    }
  }

  public getBaseUrl(): string {
    if (this.targetMode === 'EXTERNAL_FASTAPI') {
      return `${ENV_CONFIG.EXTERNAL_FASTAPI_URL}${ENV_CONFIG.API_V1_PREFIX}`;
    }
    return `${ENV_CONFIG.API_BASE_URL}${ENV_CONFIG.API_V1_PREFIX}`;
  }

  public getDisplayEndpoint(): string {
    if (this.targetMode === 'EXTERNAL_FASTAPI') {
      return `${ENV_CONFIG.EXTERNAL_FASTAPI_URL}${ENV_CONFIG.API_V1_PREFIX}`;
    }
    if (this.targetMode === 'OFFLINE_SANDBOX') {
      return 'Offline Sandbox (Simulated)';
    }
    return `${ENV_CONFIG.API_BASE_URL || window.location.origin}${ENV_CONFIG.API_V1_PREFIX}`;
  }

  public async checkBackendHealth(): Promise<{
    connected: boolean;
    latencyMs: number | null;
    version: string;
    mode: 'LIVE_BACKEND' | 'LIVE_FASTAPI' | 'DEMO_PREVIEW_SANDBOX';
  }> {
    if (this.targetMode === 'OFFLINE_SANDBOX') {
      this.backendReachable = false;
      this.lastLatencyMs = null;
      this.lastHealthCheckAt = new Date().toISOString();
      return {
        connected: false,
        latencyMs: null,
        version: '2.4.0-WIN (Sandbox)',
        mode: 'DEMO_PREVIEW_SANDBOX',
      };
    }

    const start = performance.now();
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2500);

    try {
      const response = await fetch(`${this.getBaseUrl()}/health`, {
        method: 'GET',
        credentials: 'include',
        headers: {
          Accept: 'application/json',
        },
        signal: controller.signal,
      });
      clearTimeout(timeoutId);

      const csrfHeader = response.headers.get('X-CSRF-Token');
      if (csrfHeader) {
        this.csrfToken = csrfHeader;
      }

      if (response.ok) {
        const latencyMs = Math.max(1, Math.round(performance.now() - start));
        this.backendReachable = true;
        this.lastLatencyMs = latencyMs;
        this.lastHealthCheckAt = new Date().toISOString();
        return {
          connected: true,
          latencyMs,
          version: '2.4.0-WIN',
          mode: this.targetMode === 'EXTERNAL_FASTAPI' ? 'LIVE_FASTAPI' : 'LIVE_BACKEND',
        };
      }
    } catch {
      clearTimeout(timeoutId);
    }

    this.backendReachable = false;
    this.lastLatencyMs = null;
    this.lastHealthCheckAt = new Date().toISOString();
    return {
      connected: false,
      latencyMs: null,
      version: '2.4.0-WIN (Preview)',
      mode: 'DEMO_PREVIEW_SANDBOX',
    };
  }

  public async request<T>(
    endpointPath: string,
    options: RequestInit = {},
    previewFallbackFactory?: () => T | Promise<T>
  ): Promise<ApiEnvelope<T>> {
    const method = (options.method || 'GET').toUpperCase();
    const headers = new Headers(options.headers || {});
    headers.set('Accept', 'application/json');

    if (options.body && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json');
    }

    if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      headers.set('X-CSRF-Token', this.csrfToken);
    }

    const fullUrl = `${this.getBaseUrl()}${endpointPath.startsWith('/') ? endpointPath : `/${endpointPath}`}`;

    if (this.targetMode !== 'OFFLINE_SANDBOX') {
      let response: Response;
      try {
        response = await fetch(fullUrl, {
          ...options,
          method,
          headers,
          credentials: 'include',
        });
      } catch {
        this.backendReachable = false;
        if (previewFallbackFactory) {
          const fallbackData = await previewFallbackFactory();
          return {
            data: fallbackData,
            meta: {
              backend_connected: false,
              is_demo_preview: true,
              timestamp: new Date().toISOString(),
              endpoint: `${method} ${ENV_CONFIG.API_V1_PREFIX}${endpointPath}`,
            },
          };
        }
        throw new Error(
          `Backend (${fullUrl}) is not connected. Switch to Integrated Backend or start the FastAPI server.`
        );
      }

      const csrfHeader = response.headers.get('X-CSRF-Token');
      if (csrfHeader) {
        this.csrfToken = csrfHeader;
      }

      this.backendReachable = true;

      if (response.ok) {
        const json = (await response.json()) as T;
        return {
          data: json,
          meta: {
            backend_connected: true,
            is_demo_preview: false,
            timestamp: new Date().toISOString(),
            endpoint: `${method} ${ENV_CONFIG.API_V1_PREFIX}${endpointPath}`,
          },
        };
      } else {
        // Backend is connected and responded with an error (e.g. 400, 403, 404, 502)
        let errorPayload: any = null;
        try {
          errorPayload = await response.json();
        } catch {
          errorPayload = { message: `HTTP ${response.status} ${response.statusText}` };
        }
        const errorMessage =
          errorPayload?.message ||
          errorPayload?.detail ||
          errorPayload?.error ||
          `Request failed with status ${response.status}`;
        throw new Error(errorMessage);
      }
    }

    if (previewFallbackFactory) {
      const fallbackData = await previewFallbackFactory();
      return {
        data: fallbackData,
        meta: {
          backend_connected: false,
          is_demo_preview: true,
          timestamp: new Date().toISOString(),
          endpoint: `${method} ${ENV_CONFIG.API_V1_PREFIX}${endpointPath}`,
        },
      };
    }

    throw new Error(
      `Backend (${fullUrl}) is not connected. Switch to Integrated Backend or start the FastAPI server.`
    );
  }
}

export const apiClient = new CentralizedApiClient();

