import React, { useState } from 'react';
import { Network, Play, ShieldCheck, Trash2 } from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { useAuth } from '../hooks/useAuth';
import { useRBAC } from '../hooks/useRBAC';
import { INITIAL_NETWORK_PORT_RESULTS } from '../data/seedPreviewData';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { StatusBadge } from '../components/ui/StatusBadge';
import { AuthorizationBanner } from '../components/common/AuthorizationBanner';
import { TargetSelector } from '../components/common/TargetSelector';

export const NetworkAssessmentPage: React.FC = () => {
  const { targets, verifyTarget, deleteTarget } = useSystemStatus();
  const { user } = useAuth();
  const { can } = useRBAC();

  const [selectedTargetId, setSelectedTargetId] = useState<string>(targets[1]?.id || targets[0]?.id || '');
  const [selectedProfile, setSelectedProfile] = useState<
    'QUICK_WEB' | 'WINDOWS_ENTERPRISE' | 'CUSTOM_BOUNDED'
  >('WINDOWS_ENTERPRISE');
  const [customPorts, setCustomPorts] = useState('22, 80, 443, 445, 3389, 5985, 8443');
  const [portResults, setPortResults] = useState(INITIAL_NETWORK_PORT_RESULTS);
  const [lastRunTimestamp, setLastRunTimestamp] = useState('2026-11-14T08:20:00Z');

  const selectedTarget = targets.find((t) => t.id === selectedTargetId);

  const handleRunNetworkScan = () => {
    if (!can('assessments:run') || !selectedTarget) return;
    setLastRunTimestamp(new Date().toISOString());
    if (selectedProfile === 'QUICK_WEB') {
      setPortResults(
        INITIAL_NETWORK_PORT_RESULTS.filter((p) => [22, 80, 443, 8080, 8443].includes(p.port))
      );
    } else {
      setPortResults(INITIAL_NETWORK_PORT_RESULTS);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
            Authorized Network Assessment
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Bounded, allowlisted TCP port reachability & non-destructive banner inspection with
            historical port diffing
          </p>
        </div>
        <StatusBadge status="ALLOWLIST ENFORCED" />
      </div>

      <AuthorizationBanner scopeNote="Operates strictly on verified domains and IP ranges in the organization's authorized_targets allowlist. Ad-hoc scanning of unregistered third-party domains, loopback (127.0.0.0/8), and cloud metadata (169.254.169.254) is unconditionally blocked." />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card
          title="Assessment Profile & Target Selector"
          subtitle="Select a bounded TCP connect profile (Max 100 ports per run)"
          className="lg:col-span-2"
        >
          <div className="space-y-4">
            <TargetSelector
              targets={targets}
              selectedTargetId={selectedTargetId}
              onChange={setSelectedTargetId}
            />

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <button
                type="button"
                onClick={() => setSelectedProfile('QUICK_WEB')}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  selectedProfile === 'QUICK_WEB'
                    ? 'bg-[#D6AE45]/15 border-[#D6AE45] text-[#F5F7FA]'
                    : 'bg-[#101318] border-[#29313B] text-[#A7B0BC]'
                }`}
              >
                <div className="text-xs font-semibold">Quick Web & Infra</div>
                <div className="text-[11px] font-mono mt-1 text-[#737E8C]">
                  Ports: 22, 53, 80, 443, 8080, 8443
                </div>
              </button>

              <button
                type="button"
                onClick={() => setSelectedProfile('WINDOWS_ENTERPRISE')}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  selectedProfile === 'WINDOWS_ENTERPRISE'
                    ? 'bg-[#D6AE45]/15 border-[#D6AE45] text-[#F5F7FA]'
                    : 'bg-[#101318] border-[#29313B] text-[#A7B0BC]'
                }`}
              >
                <div className="text-xs font-semibold">Windows Enterprise Profile</div>
                <div className="text-[11px] font-mono mt-1 text-[#737E8C]">
                  18 Ports (SMB 445, RDP 3389, WinRM, LDAP)
                </div>
              </button>

              <button
                type="button"
                onClick={() => setSelectedProfile('CUSTOM_BOUNDED')}
                className={`p-3 rounded-lg border text-left transition-colors ${
                  selectedProfile === 'CUSTOM_BOUNDED'
                    ? 'bg-[#D6AE45]/15 border-[#D6AE45] text-[#F5F7FA]'
                    : 'bg-[#101318] border-[#29313B] text-[#A7B0BC]'
                }`}
              >
                <div className="text-xs font-semibold">Custom Approved List</div>
                <div className="text-[11px] font-mono mt-1 text-[#737E8C]">
                  Bounded list (Max 100 TCP ports)
                </div>
              </button>
            </div>

            {selectedProfile === 'CUSTOM_BOUNDED' && (
              <div>
                <label
                  htmlFor="custom-ports-input"
                  className="block text-xs font-medium text-[#F5F7FA] mb-1"
                >
                  Approved Comma-Separated TCP Ports (Max 100)
                </label>
                <input
                  id="custom-ports-input"
                  type="text"
                  value={customPorts}
                  onChange={(e) => setCustomPorts(e.target.value)}
                  className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F5F7FA]"
                />
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[#29313B]">
              <div className="text-xs text-[#A7B0BC] font-mono">
                Last Preview Run: {lastRunTimestamp}
              </div>
              <Button
                variant="primary"
                icon={<Play className="w-4 h-4" />}
                disabled={!can('assessments:run') || selectedTarget?.verification_status !== 'VERIFIED'}
                onClick={handleRunNetworkScan}
              >
                Run Bounded Network Assessment
              </Button>
            </div>
          </div>
        </Card>

        <Card
          title="Organization Target Allowlist"
          subtitle="Active authorized_targets ledger"
        >
          <div className="space-y-2.5">
            {targets.map((t) => (
              <div
                key={t.id}
                className="p-3 bg-[#101318] border border-[#29313B] rounded-lg space-y-1.5"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-mono text-[#F5F7FA] truncate">{t.target_value}</span>
                  <StatusBadge status={t.verification_status} />
                </div>
                <div className="text-[11px] text-[#A7B0BC] flex items-center justify-between">
                  <span>
                    {t.target_type} · {t.environment}
                  </span>
                  <div className="flex items-center gap-1.5">
                    {t.verification_status !== 'VERIFIED' && can('targets:manage') && (
                      <button
                        type="button"
                        onClick={() => verifyTarget(t.id, user?.email || 'midhun.krishnan@myx-security.io')}
                        className="text-[#22C55E] hover:underline font-medium"
                      >
                        Approve
                      </button>
                    )}
                    {can('targets:manage') && (
                      <button
                        type="button"
                        aria-label={`Remove target ${t.target_value}`}
                        onClick={() => deleteTarget(t.id, user?.email || 'midhun.krishnan@myx-security.io')}
                        className="text-[#F05252] hover:text-[#F5F7FA] p-1"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* Port Discovery & Historical Diff Table */}
      <Card
        title={`TCP Port Discovery & Historical State Comparison — ${selectedTarget?.target_value || ''}`}
        subtitle="Highlights newly opened services (such as exposed SMB 445 or RDP 3389) since previous baseline run"
        noPadding
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-[#101318] border-b border-[#29313B] text-[11px] font-medium text-[#A7B0BC]">
                <th className="py-3 px-4">Port / Proto</th>
                <th className="py-3 px-4">Service</th>
                <th className="py-3 px-4">State</th>
                <th className="py-3 px-4">Historical Diff</th>
                <th className="py-3 px-4">Observed Banner</th>
                <th className="py-3 px-4">Risk Level</th>
                <th className="py-3 px-4">Analyst Notes</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#29313B] text-xs">
              {portResults.map((item) => (
                <tr key={item.port} className="hover:bg-[#1B222B]">
                  <td className="py-3 px-4 font-mono font-semibold text-[#F5F7FA] tabular-nums">
                    {item.port}/{item.protocol}
                  </td>
                  <td className="py-3 px-4 font-mono text-[#38BDF8]">{item.service_name}</td>
                  <td className="py-3 px-4">
                    <StatusBadge status={item.state.toUpperCase()} />
                  </td>
                  <td className="py-3 px-4 font-mono">
                    {item.change_since_last_scan === 'newly_opened' ? (
                      <span className="text-[#F05252] font-semibold">+ NEWLY OPENED</span>
                    ) : item.change_since_last_scan === 'newly_closed' ? (
                      <span className="text-[#22C55E]">- NEWLY CLOSED</span>
                    ) : (
                      <span className="text-[#737E8C]">UNCHANGED</span>
                    )}
                  </td>
                  <td className="py-3 px-4 font-mono text-[#A7B0BC]">
                    {item.banner || '—'}
                  </td>
                  <td className="py-3 px-4">
                    <SeverityBadge severity={item.risk_level} />
                  </td>
                  <td className="py-3 px-4 text-[#A7B0BC]">{item.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
};
