import React, { useState } from 'react';
import { RefreshCw, Lock, CheckCircle2 } from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { useRBAC } from '../hooks/useRBAC';
import { IntegrationProviderCode } from '../types/integrations.types';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { CodeEvidenceBlock } from '../components/ui/CodeEvidenceBlock';

export const IntegrationsPage: React.FC = () => {
  const { integrations, testIntegrationConnection } = useSystemStatus();
  const { can } = useRBAC();
  const [testBanner, setTestBanner] = useState<string | null>(null);

  const handleTest = (provider: IntegrationProviderCode) => {
    const res = testIntegrationConnection(provider);
    setTestBanner(`[${provider}] Connectivity Check: ${res.message}`);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
            Backend Integrations & Live Connectivity Health
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Strict Honest-State Reporting: Connected, Disconnected, Misconfigured, or Unavailable ·
            Zero client-side secret exposure
          </p>
        </div>
        <StatusBadge status="SERVER-SIDE ENV MANAGED" />
      </div>

      {testBanner && (
        <div className="p-3.5 bg-[#101318] border border-[#38BDF8]/40 rounded-lg flex items-center gap-2.5 text-xs text-[#38BDF8]">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{testBanner}</span>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {integrations.map((intg) => (
          <Card
            key={intg.provider}
            title={intg.display_name}
            subtitle={intg.category}
            headerAction={<StatusBadge status={intg.status} />}
          >
            <div className="space-y-3 text-xs">
              <p className="text-[#A7B0BC] leading-relaxed">{intg.description}</p>

              <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg space-y-1.5 font-mono">
                <div className="flex justify-between">
                  <span className="text-[#737E8C]">Backend Env Var:</span>
                  <span className="text-[#38BDF8]">{intg.env_var_name}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-[#737E8C]">Fernet/AES-GCM Vault:</span>
                  <span className="text-[#F5F7FA] inline-flex items-center gap-1">
                    <Lock className="w-3 h-3 text-[#22C55E]" />
                    {intg.has_configured_secret
                      ? `Configured (${intg.masked_secret_suffix})`
                      : 'Not Configured in Env'}
                  </span>
                </div>
                {Object.entries(intg.non_sensitive_config).map(([k, v]) => (
                  <div key={k} className="flex justify-between">
                    <span className="text-[#737E8C]">{k}:</span>
                    <span className="text-[#A7B0BC]">{v}</span>
                  </div>
                ))}
              </div>

              {intg.last_error_message && (
                <div className="p-2.5 bg-[#F59E0B]/10 border border-[#F59E0B]/30 rounded text-[11px] text-[#F59E0B]">
                  {intg.last_error_message}
                </div>
              )}

              <div className="flex items-center justify-between pt-2 border-t border-[#29313B]">
                <span className="text-[11px] font-mono text-[#737E8C]">
                  Last Tested: {intg.last_tested_at || 'Never'}
                </span>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={<RefreshCw className="w-3.5 h-3.5" />}
                  disabled={!can('integrations:view')}
                  onClick={() => handleTest(intg.provider)}
                >
                  Test Connectivity
                </Button>
              </div>
            </div>
          </Card>
        ))}
      </div>

      <CodeEvidenceBlock
        title="Backend Environment Configuration Template (backend/.env.example)"
        language="dotenv"
        code={`# Configure in Google Antigravity backend/.env (Never exposed to frontend browser):
DATABASE_URL=postgresql+psycopg://myx_admin:CHANGE_ME@localhost:5432/myx_ai_windows
ENCRYPTION_MASTER_KEY=generate_via_cryptography_fernet_generate_key
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_PRIMARY_MODEL=gemini-2.5-flash
GEMINI_ADVANCED_MODEL=gemini-2.5-pro
GEMINI_FAST_MODEL=gemini-2.5-flash-lite
GEMINI_EMBEDDING_MODEL=gemini-embedding-001
RESEND_API_KEY=re_your_resend_key
GOOGLE_SAFE_BROWSING_API_KEY=your_gsb_key
VIRUSTOTAL_API_KEY=your_vt_key`}
      />
    </div>
  );
};
