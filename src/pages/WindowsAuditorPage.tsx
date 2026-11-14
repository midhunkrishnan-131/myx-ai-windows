import React, { useState } from 'react';
import {
  MonitorCheck,
  PlusCircle,
  ShieldAlert,
  KeyRound,
  Ban,
  HardDrive,
  Cpu,
} from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { useAuth } from '../hooks/useAuth';
import { useRBAC } from '../hooks/useRBAC';
import { windowsAgentService } from '../services/windowsAgent.service';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { StatusBadge } from '../components/ui/StatusBadge';
import { CodeEvidenceBlock } from '../components/ui/CodeEvidenceBlock';
import { ConfirmationModal } from '../components/ui/ConfirmationModal';

export const WindowsAuditorPage: React.FC = () => {
  const {
    windowsAgents,
    windowsInventoryByAgent,
    windowsPostureByAgent,
    windowsSockets,
    enrollWindowsAgent,
    revokeWindowsAgent,
  } = useSystemStatus();
  const { user } = useAuth();
  const { can } = useRBAC();

  const [selectedAgentId, setSelectedAgentId] = useState<string>(windowsAgents[0]?.id || '');
  const [newHostname, setNewHostname] = useState('');
  const [newDisplayName, setNewDisplayName] = useState('');
  const [newEdition, setNewEdition] = useState('Microsoft Windows 11 Pro');
  const [enrollmentBundle, setEnrollmentBundle] = useState<{
    token: string;
    cli: string;
    hostname: string;
  } | null>(null);
  const [agentToRevoke, setAgentToRevoke] = useState<string | null>(null);

  const selectedAgent =
    windowsAgents.find((a) => a.id === selectedAgentId) || windowsAgents[0];
  const inventory = windowsInventoryByAgent[selectedAgent?.id];
  const postureChecks = windowsPostureByAgent[selectedAgent?.id] || [];

  const handleEnrollSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!can('agents:manage') || !newHostname.trim()) return;

    const tokenRes = await windowsAgentService.generateEnrollmentToken(
      newHostname.trim(),
      newDisplayName.trim() || `${newHostname.trim()} Endpoint`
    );

    const enrolled = enrollWindowsAgent(
      newHostname.trim(),
      newDisplayName.trim() || `${newHostname.trim()} Endpoint`,
      newEdition,
      user?.email || 'midhun.krishnan@myx-security.io'
    );

    setSelectedAgentId(enrolled.id);
    setEnrollmentBundle({
      token: tokenRes.data.enrollment_token,
      cli: tokenRes.data.cli_command,
      hostname: enrolled.hostname,
    });
    setNewHostname('');
    setNewDisplayName('');
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
            Windows Security Auditor & Local Agent Manager
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Exclusively engineered for Microsoft Windows 10 (20H2+) & Windows 11 (21H2–24H2) across
            Home, Pro, Enterprise & Education editions
          </p>
        </div>
        <StatusBadge status="WINDOWS 10 / 11 ONLY" />
      </div>

      {/* Agent Selector & Enrollment Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card
          title="Enrolled Windows 10/11 Local Agents"
          subtitle="Select an enrolled Windows host to inspect Defender, Firewall, BitLocker, UAC, RDP, and sockets"
          className="lg:col-span-2"
        >
          <div className="space-y-3">
            {windowsAgents.map((agent) => {
              const isSelected = agent.id === selectedAgent?.id;
              return (
                <div
                  key={agent.id}
                  onClick={() => setSelectedAgentId(agent.id)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') setSelectedAgentId(agent.id);
                  }}
                  className={`p-3.5 rounded-lg border transition-colors cursor-pointer flex flex-col sm:flex-row sm:items-center justify-between gap-3 ${
                    isSelected
                      ? 'bg-[#D6AE45]/15 border-[#D6AE45]'
                      : 'bg-[#101318] border-[#29313B] hover:bg-[#1B222B]'
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-bold text-[#F5F7FA]">
                        {agent.hostname}
                      </span>
                      <StatusBadge status={agent.status} />
                      <span className="text-xs font-mono text-[#38BDF8]">
                        [{agent.privilege_level}]
                      </span>
                    </div>
                    <div className="text-xs text-[#A7B0BC]">
                      {agent.display_name} · {agent.os_edition} ({agent.os_version} Build{' '}
                      {agent.os_build})
                    </div>
                    <div className="text-[11px] font-mono text-[#737E8C]">
                      Last Heartbeat: {agent.last_heartbeat_at} · IP: {agent.last_ip_address}
                    </div>
                  </div>
                  {agent.status !== 'REVOKED' && can('agents:manage') && (
                    <Button
                      variant="danger"
                      size="sm"
                      icon={<Ban className="w-3.5 h-3.5" />}
                      onClick={(e) => {
                        e.stopPropagation();
                        setAgentToRevoke(agent.id);
                      }}
                    >
                      Revoke Agent
                    </Button>
                  )}
                </div>
              );
            })}
          </div>
        </Card>

        <Card
          title="Enroll New Windows 10/11 Agent"
          subtitle="Generates a single-use 15-minute SHA-256 hashed enrollment token"
        >
          <form onSubmit={handleEnrollSubmit} className="space-y-3">
            <div>
              <label htmlFor="win-hostname" className="block text-xs font-medium text-[#F5F7FA] mb-1">
                Windows Hostname
              </label>
              <input
                id="win-hostname"
                type="text"
                placeholder="WIN11-SECOPS-04"
                value={newHostname}
                onChange={(e) => setNewHostname(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F5F7FA]"
              />
            </div>

            <div>
              <label htmlFor="win-desc" className="block text-xs font-medium text-[#F5F7FA] mb-1">
                Descriptive Host Label
              </label>
              <input
                id="win-desc"
                type="text"
                placeholder="SOC Analyst Workstation #4"
                value={newDisplayName}
                onChange={(e) => setNewDisplayName(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs text-[#F5F7FA]"
              />
            </div>

            <div>
              <label htmlFor="win-edition" className="block text-xs font-medium text-[#F5F7FA] mb-1">
                Target Windows Edition
              </label>
              <select
                id="win-edition"
                value={newEdition}
                onChange={(e) => setNewEdition(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs text-[#F5F7FA]"
              >
                <option value="Microsoft Windows 11 Pro">Microsoft Windows 11 Pro (23H2/24H2)</option>
                <option value="Microsoft Windows 11 Enterprise">Microsoft Windows 11 Enterprise</option>
                <option value="Microsoft Windows 11 Home">Microsoft Windows 11 Home</option>
                <option value="Microsoft Windows 10 Pro">Microsoft Windows 10 Pro (22H2)</option>
                <option value="Microsoft Windows 10 Home">Microsoft Windows 10 Home (22H2)</option>
              </select>
            </div>

            <Button
              type="submit"
              variant="primary"
              size="sm"
              icon={<KeyRound className="w-3.5 h-3.5" />}
              className="w-full"
              disabled={!can('agents:manage') || !newHostname.trim()}
            >
              Generate Single-Use Enrollment Token
            </Button>
          </form>

          {enrollmentBundle && (
            <div className="mt-4 pt-3 border-t border-[#29313B] space-y-2">
              <div className="text-xs font-semibold text-[#22C55E]">
                Token Issued for {enrollmentBundle.hostname} (Valid 15m):
              </div>
              <div className="p-2 bg-[#080A0D] border border-[#29313B] rounded font-mono text-xs text-[#38BDF8] break-all">
                {enrollmentBundle.token}
              </div>
              <CodeEvidenceBlock
                title="Run on Windows 10/11 PowerShell"
                code={enrollmentBundle.cli}
                language="powershell"
                secretsRedacted={false}
              />
            </div>
          )}
        </Card>
      </div>

      {/* System Inventory for Selected Windows Host */}
      {inventory && (
        <Card
          title={`System Inventory & Partition Telemetry — ${inventory.hostname}`}
          subtitle={`${inventory.os_caption} (${inventory.os_version} · Build ${inventory.os_build}) · Token: ${inventory.privilege_level}`}
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs">
            <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg space-y-1">
              <div className="text-[#A7B0BC] flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-[#38BDF8]" />
                <span>Processor & Utilization</span>
              </div>
              <div className="font-semibold text-[#F5F7FA] truncate">{inventory.cpu_model}</div>
              <div className="font-mono text-[#737E8C]">
                {inventory.physical_cores}C / {inventory.logical_cores}T · Load:{' '}
                {inventory.cpu_utilization_percent}%
              </div>
            </div>

            <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg space-y-1">
              <div className="text-[#A7B0BC]">Memory & Uptime</div>
              <div className="font-mono font-semibold text-[#F5F7FA]">
                {inventory.ram_used_gb} GB / {inventory.ram_total_gb} GB Used
              </div>
              <div className="font-mono text-[#737E8C]">
                Uptime: {inventory.uptime_hours} hrs · Domain: {inventory.domain_or_workgroup}
              </div>
            </div>

            <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg space-y-1">
              <div className="text-[#A7B0BC]">Windows KB Security Updates</div>
              <div className="font-mono font-semibold text-[#F5F7FA]">
                Latest: {inventory.hotfixes[0]?.hotfix_id || 'None'}
              </div>
              <div className="font-mono text-[#737E8C]">
                {inventory.days_since_last_update} days since last KB update
              </div>
            </div>

            <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg space-y-1">
              <div className="text-[#A7B0BC] flex items-center gap-1.5">
                <HardDrive className="w-3.5 h-3.5 text-[#38BDF8]" />
                <span>Volumes & BitLocker</span>
              </div>
              {inventory.disks.map((d) => (
                <div key={d.mountpoint} className="font-mono text-[11px] flex justify-between">
                  <span className="text-[#F5F7FA]">
                    {d.mountpoint} ({d.filesystem})
                  </span>
                  <span
                    className={
                      d.bitlocker_status === 'FullyEncrypted'
                        ? 'text-[#22C55E]'
                        : 'text-[#F59E0B]'
                    }
                  >
                    {d.bitlocker_status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </Card>
      )}

      {/* Defensive Security Posture Checks */}
      <Card
        title={`Defensive Windows 10/11 Security Posture Checks — ${selectedAgent?.hostname}`}
        subtitle="Edition-aware & privilege-aware read-only collectors (Zero remote shell / Zero arbitrary OS command execution)"
      >
        <div className="space-y-4">
          {postureChecks.map((chk) => (
            <div
              key={chk.id}
              className="p-4 bg-[#101318] border border-[#29313B] rounded-lg space-y-3"
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div>
                  <span className="text-xs font-mono text-[#38BDF8]">{chk.category}</span>
                  <h3 className="text-sm font-semibold text-[#F5F7FA] mt-0.5">{chk.title}</h3>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-[11px] font-mono text-[#A7B0BC]">
                    Req: {chk.privilege_required}
                  </span>
                  <SeverityBadge severity={chk.severity} />
                  <StatusBadge status={chk.status} />
                </div>
              </div>

              <p className="text-xs text-[#A7B0BC]">{chk.explanation}</p>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                <CodeEvidenceBlock
                  title={`Collector Telemetry (${chk.evidence_source})`}
                  code={chk.raw_telemetry}
                  language="powershell"
                />
                <CodeEvidenceBlock
                  title="Recommended Hardening PowerShell"
                  code={chk.remediation_powershell}
                  language="powershell"
                  isRemediationSnippet
                />
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Listening TCP/UDP Network Sockets */}
      <Card
        title="Process-Bound Listening Network Sockets (psutil.net_connections)"
        subtitle="Flags risky services bound to 0.0.0.0 / :: vs safe loopback 127.0.0.1"
        noPadding
      >
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="bg-[#101318] border-b border-[#29313B] text-[11px] font-medium text-[#A7B0BC]">
                <th className="py-3 px-4">Bind Address : Port</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">PID & Owning Process</th>
                <th className="py-3 px-4">Exposure Scope</th>
                <th className="py-3 px-4">Risk</th>
                <th className="py-3 px-4">Defensive Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#29313B] text-xs">
              {windowsSockets.map((sock, idx) => (
                <tr key={idx} className="hover:bg-[#1B222B]">
                  <td className="py-3 px-4 font-mono font-semibold text-[#F5F7FA] tabular-nums">
                    {sock.local_address}:{sock.local_port}
                  </td>
                  <td className="py-3 px-4 font-mono text-[#38BDF8]">{sock.protocol}</td>
                  <td className="py-3 px-4 font-mono text-[#F5F7FA]">
                    PID {sock.pid} — {sock.process_name}
                  </td>
                  <td className="py-3 px-4 font-mono text-[#A7B0BC]">{sock.exposure_scope}</td>
                  <td className="py-3 px-4">
                    <SeverityBadge severity={sock.risk_level} />
                  </td>
                  <td className="py-3 px-4 text-[#A7B0BC]">{sock.notes}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <ConfirmationModal
        isOpen={Boolean(agentToRevoke)}
        title="Revoke Windows Local Agent Credentials"
        description="Revoking this Windows 10/11 agent immediately invalidates its bearer token and HMAC secret. Any subsequent telemetry submissions from this host will be rejected with HTTP 401."
        confirmLabel="Revoke Agent Immediately"
        variant="danger"
        onCancel={() => setAgentToRevoke(null)}
        onConfirm={() => {
          if (agentToRevoke) {
            revokeWindowsAgent(agentToRevoke, user?.email || 'midhun.krishnan@myx-security.io');
            setAgentToRevoke(null);
          }
        }}
      />
    </div>
  );
};
