import React, { useState } from 'react';
import { History, GitCompare } from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';

export const AssessmentHistoryPage: React.FC = () => {
  const { assessments } = useSystemStatus();
  const [moduleFilter, setModuleFilter] = useState<string>('ALL');

  const filtered = assessments.filter(
    (a) => moduleFilter === 'ALL' || a.module_type === moduleFilter
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
            Unified Assessment History & Posture Diff Ledger
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Chronological audit trail of Website, Network, Wi-Fi, Windows 10/11, SSL/TLS, DNS, and
            LinkGuard runs
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {['ALL', 'WEBSITE', 'WINDOWS', 'NETWORK'].map((m) => (
            <button
              key={m}
              type="button"
              onClick={() => setModuleFilter(m)}
              className={`px-2.5 py-1 rounded text-xs font-mono transition-colors ${
                moduleFilter === m
                  ? 'bg-[#D6AE45] text-[#F5F7FA]'
                  : 'bg-[#141920] text-[#A7B0BC] border border-[#29313B]'
              }`}
            >
              {m}
            </button>
          ))}
        </div>
      </div>

      <Card
        title={`Assessment Runs (${filtered.length})`}
        subtitle="All runs in AI Studio browser sandbox are tagged with is_demo_preview = true until FastAPI backend is connected"
        noPadding
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-[#101318] border-b border-[#29313B] text-[11px] font-medium text-[#A7B0BC]">
                <th className="py-3 px-4">Run ID</th>
                <th className="py-3 px-4">Module</th>
                <th className="py-3 px-4">Authorized Target</th>
                <th className="py-3 px-4">Profile</th>
                <th className="py-3 px-4 text-right">Pass / Warn / Fail</th>
                <th className="py-3 px-4">Initiated By</th>
                <th className="py-3 px-4">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#29313B] text-xs">
              {filtered.map((run) => (
                <tr key={run.id} className="hover:bg-[#1B222B]">
                  <td className="py-3 px-4 font-mono text-[#38BDF8]">{run.id}</td>
                  <td className="py-3 px-4 font-mono text-[#F5F7FA]">{run.module_type}</td>
                  <td className="py-3 px-4 font-mono text-[#F5F7FA]">{run.target_display}</td>
                  <td className="py-3 px-4 text-[#A7B0BC]">{run.profile_name}</td>
                  <td className="py-3 px-4 text-right font-mono tabular-nums">
                    <span className="text-[#22C55E]">{run.summary.passed}P</span> /{' '}
                    <span className="text-[#F59E0B]">{run.summary.warnings}W</span> /{' '}
                    <span className="text-[#F05252]">{run.summary.failed}F</span>
                  </td>
                  <td className="py-3 px-4 font-mono text-[#A7B0BC]">
                    {run.initiated_by_email}
                  </td>
                  <td className="py-3 px-4">
                    <StatusBadge status={run.status} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card
        title="Historical Assessment Posture Diff Comparison"
        subtitle="GET /api/v1/assessments/compare?base_id=asm-win-2026-01&target_id=asm-win-2026-02"
      >
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
          <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg space-y-1">
            <div className="text-[#A7B0BC] flex items-center gap-1.5">
              <GitCompare className="w-3.5 h-3.5 text-[#22C55E]" />
              <span>Remediated Since Baseline</span>
            </div>
            <div className="font-mono font-semibold text-[#22C55E]">
              +2 Controls Remediated
            </div>
            <div className="text-[#737E8C]">
              SMBv1 disabled · Windows Defender Tamper Protection enabled
            </div>
          </div>
          <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg space-y-1">
            <div className="text-[#A7B0BC]">Newly Detected Regressions</div>
            <div className="font-mono font-semibold text-[#F05252]">
              1 New Critical Exposure
            </div>
            <div className="text-[#737E8C]">
              TCP/3389 RDP enabled without NLA on WIN11-SECOPS-01
            </div>
          </div>
          <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg space-y-1">
            <div className="text-[#A7B0BC]">Unchanged Open Findings</div>
            <div className="font-mono font-semibold text-[#F59E0B]">
              3 Persistent Findings
            </div>
            <div className="text-[#737E8C]">
              Volume D: BitLocker Off · Portal CSP unsafe-inline · TLSv1.1 active
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};
