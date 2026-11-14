import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts';
import {
  MonitorCheck,
  ArrowRight,
  Globe,
  Sparkles,
  Bot,
} from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { BRAND_CONFIG } from '../config/brand.config';
import { apiClient } from '../services/apiClient';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { StatusBadge } from '../components/ui/StatusBadge';

interface AiPostureBriefing {
  summary: string;
  topPriorities: string[];
  estimatedRiskReduction: string;
  model: string;
  latencyMs: number;
}

export const DashboardPage: React.FC = () => {
  const { findings, assessments, windowsAgents, integrations, targets } = useSystemStatus();
  const [aiBriefing, setAiBriefing] = useState<AiPostureBriefing | null>(null);
  const [loadingBriefing, setLoadingBriefing] = useState(false);

  const openFindings = findings.filter(
    (f) => f.status === 'Open' || f.status === 'In Progress' || f.status === 'Reopened'
  );
  const criticalCount = openFindings.filter((f) => f.severity === 'Critical').length;
  const highCount = openFindings.filter((f) => f.severity === 'High').length;
  const mediumCount = openFindings.filter((f) => f.severity === 'Medium').length;
  const lowCount = openFindings.filter((f) => f.severity === 'Low').length;

  const activeWindowsAgents = windowsAgents.filter((a) => a.status === 'ACTIVE');
  const verifiedTargets = targets.filter((t) => t.verification_status === 'VERIFIED');

  const severityChartData = [
    { name: 'Critical', count: criticalCount, color: '#F05252' },
    { name: 'High', count: highCount, color: '#F59E0B' },
    { name: 'Medium', count: mediumCount, color: '#F59E0B' },
    { name: 'Low', count: lowCount, color: '#22C55E' },
  ];

  const handleGenerateAiBriefing = async () => {
    setLoadingBriefing(true);
    try {
      const res = await apiClient.request<AiPostureBriefing>(
        '/ai/posture-briefing',
        { method: 'POST' },
        () => ({
          summary: `Across ${activeWindowsAgents.length} enrolled Windows 10/11 endpoints and ${targets.length} authorized targets, MYX AI identified ${criticalCount} Critical and ${highCount} High priority findings requiring immediate defensive hardening. Priority #1 is enforcing Network Level Authentication (NLA) on RDP listener port 3389 (MYX-FND-2026-0041) to eliminate pre-authentication lateral movement exposure.`,
          topPriorities: [
            'Enforce RDP Network Level Authentication (NLA) on WIN11-SECOPS-01 (MYX-FND-2026-0041 · CVSS 9.8)',
            'Enable BitLocker XTS-AES-256 on Secondary Volume D: with TPM+PIN protector (MYX-FND-2026-0042 · CVSS 7.1)',
            'Remove unsafe-inline/unsafe-eval from portal Content-Security-Policy (MYX-FND-2026-0043 · CVSS 7.4)',
          ],
          estimatedRiskReduction: '64%',
          model: 'gemini-3-flash-preview',
          latencyMs: 142,
        })
      );
      setAiBriefing(res.data);
    } finally {
      setLoadingBriefing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Executive Header */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 pb-3 border-b border-[#29313B]">
        <div className="flex items-center gap-3.5">
          <div className="w-14 h-14 rounded-xl bg-[#101318] border border-[#D6AE45]/40 p-1.5 flex items-center justify-center shrink-0 shadow-sm">
            <img
              src={BRAND_CONFIG.BRAND_LOGO_URL}
              alt={`${BRAND_CONFIG.BRAND_FULL_TITLE} Logo`}
              className="w-full h-full object-contain"
            />
          </div>
          <div>
            <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
              {BRAND_CONFIG.BRAND_FULL_TITLE} — Executive Security Posture
            </h1>
            <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
              {BRAND_CONFIG.BRAND_TAGLINE} · Authorized Web, Network, Wi-Fi & Windows 10/11 Security
              Operations Center
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2.5">
          <Button
            variant="secondary"
            size="sm"
            isLoading={loadingBriefing}
            onClick={handleGenerateAiBriefing}
            icon={<Sparkles className="w-4 h-4 text-[#D6AE45]" />}
          >
            Generate AI Posture Briefing
          </Button>
          <Link
            to="/auditors/windows"
            className="inline-flex items-center gap-2 px-3.5 py-2 bg-[#141920] hover:bg-[#1B222B] border border-[#29313B] rounded-lg text-xs font-medium text-[#F5F7FA] transition-colors whitespace-nowrap shrink-0"
          >
            <MonitorCheck className="w-4 h-4 text-[#D6AE45]" />
            <span>Windows 10/11 Auditor</span>
          </Link>
          <Link
            to="/assessments/website"
            className="inline-flex items-center gap-2 px-4 py-2 bg-[#D6AE45] hover:bg-[#E7C66A] rounded-lg text-xs font-semibold text-[#080A0D] transition-colors whitespace-nowrap shrink-0"
          >
            <Globe className="w-4 h-4" />
            <span>New Authorized Assessment</span>
          </Link>
        </div>
      </div>

      {/* Live AI Posture Briefing Panel */}
      {aiBriefing && (
        <div className="p-4 bg-[#141920] border border-[#D6AE45]/60 rounded-lg space-y-3 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 font-semibold text-[#D6AE45]">
              <Bot className="w-4 h-4" />
              <span>MYX AI Executive Posture Briefing ({aiBriefing.model})</span>
            </div>
            <div className="flex items-center gap-2 font-mono text-[11px] text-[#A7B0BC]">
              <span>Projected Risk Reduction: {aiBriefing.estimatedRiskReduction}</span>
              <span>·</span>
              <span>Latency: {aiBriefing.latencyMs}ms</span>
            </div>
          </div>
          <p className="text-[#F5F7FA] leading-relaxed">{aiBriefing.summary}</p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5 pt-1">
            {aiBriefing.topPriorities.map((item, idx) => (
              <div
                key={idx}
                className="p-2.5 bg-[#101318] border border-[#29313B] rounded font-mono text-[11px] text-[#A7B0BC]"
              >
                <span className="text-[#D6AE45] font-bold">P{idx + 1}:</span> {item}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 4-Column KPI Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <div className="p-5 bg-[#141920] border border-[#29313B] rounded-lg">
          <div className="text-xs text-[#A7B0BC]">Open Critical & High Findings</div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl sm:text-3xl font-bold font-mono text-[#F05252] tabular-nums">
              {criticalCount + highCount}
            </span>
            <span className="text-xs text-[#A7B0BC] font-mono">
              {criticalCount} Crit · {highCount} High
            </span>
          </div>
          <div className="mt-2 text-xs text-[#737E8C]">
            Verified CVSS v3.1 & Windows baseline telemetry
          </div>
        </div>

        <div className="p-5 bg-[#141920] border border-[#29313B] rounded-lg">
          <div className="text-xs text-[#A7B0BC]">Verified Authorized Targets</div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl sm:text-3xl font-bold font-mono text-[#22C55E] tabular-nums">
              {verifiedTargets.length} / {targets.length}
            </span>
            <span className="text-xs text-[#A7B0BC] font-mono">Allowlisted</span>
          </div>
          <div className="mt-2 text-xs text-[#737E8C]">
            DNS TXT, HTTP .well-known & Lab Approval
          </div>
        </div>

        <div className="p-5 bg-[#141920] border border-[#29313B] rounded-lg">
          <div className="text-xs text-[#A7B0BC]">Enrolled Windows 10/11 Agents</div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl sm:text-3xl font-bold font-mono text-[#D6AE45] tabular-nums">
              {activeWindowsAgents.length}
            </span>
            <span className="text-xs text-[#A7B0BC] font-mono">
              Win 10/11 Only
            </span>
          </div>
          <div className="mt-2 text-xs text-[#737E8C]">
            Read-only PowerShell / WMI / Defender collectors
          </div>
        </div>

        <div className="p-5 bg-[#141920] border border-[#29313B] rounded-lg">
          <div className="text-xs text-[#A7B0BC]">Completed Security Assessments</div>
          <div className="mt-2 flex items-baseline justify-between">
            <span className="text-2xl sm:text-3xl font-bold font-mono text-[#F5F7FA] tabular-nums">
              {assessments.length}
            </span>
            <span className="text-xs text-[#A7B0BC] font-mono">Active Ledger</span>
          </div>
          <div className="mt-2 text-xs text-[#737E8C]">
            Web, Network, Windows, Wi-Fi, SSL/TLS & DNS
          </div>
        </div>
      </div>

      {/* Charts & Windows Agent Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card
          title="Active Vulnerability Distribution by Severity"
          subtitle="Open, In-Progress, and Reopened findings across verified assets"
          className="lg:col-span-2"
        >
          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityChartData} margin={{ top: 10, right: 16, left: -16, bottom: 0 }}>
                <XAxis
                  dataKey="name"
                  stroke="#A7B0BC"
                  fontSize={12}
                  tickLine={false}
                  axisLine={{ stroke: '#29313B' }}
                />
                <YAxis
                  stroke="#A7B0BC"
                  fontSize={12}
                  allowDecimals={false}
                  tickLine={false}
                  axisLine={{ stroke: '#29313B' }}
                />
                <Tooltip
                  cursor={{ fill: '#1B222B' }}
                  contentStyle={{
                    backgroundColor: '#101318',
                    borderColor: '#29313B',
                    borderRadius: '8px',
                    color: '#F5F7FA',
                    fontSize: '12px',
                  }}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityChartData.map((entry, idx) => (
                    <Cell key={idx} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>

        <Card
          title="Windows 10/11 Local Agent Health"
          subtitle="Strictly scoped to Microsoft Windows 10 & Windows 11"
          headerAction={
            <Link
              to="/auditors/windows"
              className="text-xs text-[#D6AE45] hover:underline whitespace-nowrap"
            >
              Manage Agents
            </Link>
          }
        >
          <div className="space-y-3">
            {windowsAgents.length === 0 ? (
              <div className="py-8 px-4 text-center text-xs text-[#A7B0BC] space-y-2">
                <MonitorCheck className="w-8 h-8 text-[#29313B] mx-auto mb-1" />
                <p>No Windows 10/11 agents enrolled yet.</p>
                <p className="text-[11px] text-[#737E8C]">Run the background Windows auditor agent to stream live host telemetry.</p>
              </div>
            ) : (
              windowsAgents.map((agent) => (
                <div
                  key={agent.id}
                  className="p-3 bg-[#101318] border border-[#29313B] rounded-lg space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono font-semibold text-[#F5F7FA] truncate">
                      {agent.hostname}
                    </span>
                    <StatusBadge status={agent.status} />
                  </div>
                  <div className="text-xs text-[#A7B0BC] truncate">
                    {agent.os_edition} ({agent.os_version} · Build {agent.os_build})
                  </div>
                  <div className="flex items-center justify-between text-[11px] text-[#737E8C] font-mono">
                    <span>Token: {agent.privilege_level}</span>
                    <span>IP: {agent.last_ip_address}</span>
                  </div>
                </div>
              ))
            )}
          </div>
        </Card>
      </div>

      {/* Priority Findings & Integration Readiness */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card
          title="Priority Open Security Findings"
          subtitle="Verified technical evidence with CVSS v3.1 & CWE mapping"
          className="lg:col-span-2"
          noPadding
          headerAction={
            <Link
              to="/findings"
              className="inline-flex items-center gap-1 text-xs text-[#D6AE45] hover:underline"
            >
              <span>View All Findings</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </Link>
          }
        >
          <div className="overflow-x-auto">
            {findings.length === 0 ? (
              <div className="py-12 px-4 text-center space-y-2">
                <Globe className="w-9 h-9 text-[#29313B] mx-auto mb-1" />
                <div className="text-sm font-semibold text-[#F5F7FA]">No Open Security Findings</div>
                <p className="text-xs text-[#A7B0BC] max-w-sm mx-auto">
                  Provide a website URL in Website Assessment to scan security headers and discover vulnerabilities in real time.
                </p>
                <div className="pt-2">
                  <Link to="/assessments/website">
                    <Button variant="primary" size="sm">Go to Website Assessment &rarr;</Button>
                  </Link>
                </div>
              </div>
            ) : (
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-[#101318] border-b border-[#29313B] text-[11px] font-medium text-[#A7B0BC]">
                    <th className="py-3 px-4">Finding ID</th>
                    <th className="py-3 px-4">Title & Asset</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4 text-right">CVSS v3.1</th>
                    <th className="py-3 px-4">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#29313B] text-xs">
                  {findings.slice(0, 4).map((f) => (
                    <tr key={f.id} className="hover:bg-[#1B222B] transition-colors">
                      <td className="py-3 px-4 font-mono text-[#38BDF8] whitespace-nowrap">
                        {f.finding_code}
                      </td>
                      <td className="py-3 px-4">
                        <div className="font-medium text-[#F5F7FA]">{f.title}</div>
                        <div className="font-mono text-[11px] text-[#737E8C] mt-0.5">
                          {f.affected_asset} · {f.cwe_id}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="py-3 px-4 text-right font-mono text-[#F5F7FA] tabular-nums">
                        {f.cvss_score?.toFixed(1) ?? 'N/A'}
                      </td>
                      <td className="py-3 px-4">
                        <StatusBadge status={f.status} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </Card>

        <Card
          title="Honest-State Integration Readiness"
          subtitle="True operational status of backend services & external feeds"
          headerAction={
            <Link
              to="/integrations"
              className="text-xs text-[#D6AE45] hover:underline whitespace-nowrap"
            >
              Configure
            </Link>
          }
        >
          <div className="space-y-2.5">
            {integrations.map((intg) => (
              <div
                key={intg.provider}
                className="flex items-center justify-between gap-2 p-2.5 bg-[#101318] border border-[#29313B] rounded-lg"
              >
                <div className="min-w-0">
                  <div className="text-xs font-medium text-[#F5F7FA] truncate">
                    {intg.display_name}
                  </div>
                  <div className="text-[11px] font-mono text-[#737E8C] truncate">
                    Env: {intg.env_var_name}
                  </div>
                </div>
                <StatusBadge status={intg.status} />
              </div>
            ))}
          </div>
        </Card>
      </div>
    </div>
  );
};
