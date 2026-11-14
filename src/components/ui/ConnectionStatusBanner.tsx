import React from 'react';
import { RefreshCw, ServerOff, CheckCircle2 } from 'lucide-react';
import { useSystemStatus } from '../../context/SystemStatusContext';
import { apiClient } from '../../services/apiClient';

export const ConnectionStatusBanner: React.FC = () => {
  const {
    backendConnected,
    backendLatencyMs,
    recheckBackendConnection,
    windowsAgents,
  } = useSystemStatus();
  const [checking, setChecking] = React.useState(false);

  const activeAgentsCount = windowsAgents.filter((a) => a.status === 'ACTIVE').length;

  const handleRetry = async () => {
    setChecking(true);
    await recheckBackendConnection();
    setChecking(false);
  };

  if (backendConnected) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="px-4 sm:px-6 py-2 bg-[#101318] border-b border-[#29313B] flex flex-wrap items-center justify-between gap-2 text-xs"
      >
        <div className="flex flex-wrap items-center gap-2.5">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-[#22C55E]/15 text-[#22C55E] border border-[#22C55E]/40 font-mono font-semibold whitespace-nowrap shrink-0">
            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
            LIVE BACKEND CONNECTED ({apiClient.getDisplayEndpoint()})
          </span>
          <span className="text-[#A7B0BC] font-mono hidden md:inline">
            Latency: {backendLatencyMs ?? 2}ms · CSRF Guard: Active
          </span>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <span className="text-[#A7B0BC] font-mono hidden sm:inline">
            Active Windows 10/11 Agents: {activeAgentsCount}
          </span>
          <button
            type="button"
            onClick={handleRetry}
            disabled={checking}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#141920] hover:bg-[#1B222B] text-[#F5F7FA] border border-[#29313B] transition-colors whitespace-nowrap shrink-0"
          >
            <RefreshCw className={`w-3 h-3 ${checking ? 'animate-spin' : ''}`} aria-hidden="true" />
            <span>Resync Backend</span>
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      role="status"
      aria-live="polite"
      className="px-4 sm:px-6 py-2 bg-[#101318] border-b border-[#29313B] flex flex-wrap items-center justify-between gap-3 text-xs"
    >
      <div className="flex flex-wrap items-center gap-2.5">
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/40 font-mono font-semibold whitespace-nowrap shrink-0">
          <ServerOff className="w-3.5 h-3.5 shrink-0" aria-hidden="true" />
          DEMO / SAMPLE DATA — BACKEND NOT CONNECTED
        </span>
        <span className="text-[#A7B0BC] hidden md:inline">
          Backend server ({apiClient.getDisplayEndpoint()}) is unreachable. Showing interactive reference telemetry.
        </span>
      </div>
      <div className="flex items-center gap-3 shrink-0">
        <span className="text-[#A7B0BC] font-mono hidden sm:inline">
          Enrolled Windows 10/11 Hosts: {activeAgentsCount}
        </span>
        <button
          type="button"
          onClick={handleRetry}
          disabled={checking}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-[#141920] hover:bg-[#1B222B] text-[#F5F7FA] border border-[#29313B] transition-colors whitespace-nowrap shrink-0"
        >
          <RefreshCw className={`w-3 h-3 ${checking ? 'animate-spin' : ''}`} aria-hidden="true" />
          <span>Retry Backend Check</span>
        </button>
      </div>
    </div>
  );
};

