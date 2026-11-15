import React, { useState } from 'react';
import {
  Network,
  Play,
  ShieldCheck,
  Trash2,
  Loader2,
  CheckCircle2,
  AlertTriangle,
  Globe,
  Radio,
  Server,
  Layers,
  Activity,
} from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { useAuth } from '../hooks/useAuth';
import { useRBAC } from '../hooks/useRBAC';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { StatusBadge } from '../components/ui/StatusBadge';
import { AuthorizationBanner } from '../components/common/AuthorizationBanner';
import { TargetSelector } from '../components/common/TargetSelector';
import { ErrorState } from '../components/ui/States';
import { assessmentsService } from '../services/assessments.service';
import { NetworkPortResult, AssessmentRun } from '../types/assessment.types';
import { validateTargetSsrfGuard } from '../utils/securityLogic';

export const NetworkAssessmentPage: React.FC = () => {
  const {
    targets,
    verifyTarget,
    deleteTarget,
    addAssessmentRun,
    recheckBackendConnection,
    labTargetsAllowed,
  } = useSystemStatus();
  const { user } = useAuth();
  const { can } = useRBAC();

  // Quick Live Network Assessment state
  const [quickTargetHost, setQuickTargetHost] = useState('');
  const [quickProfile, setQuickProfile] = useState<
    'QUICK_WEB' | 'WINDOWS_ENTERPRISE' | 'CUSTOM_BOUNDED'
  >('QUICK_WEB');
  const [quickCustomPorts, setQuickCustomPorts] = useState('22, 80, 443, 8080, 8443');

  // Target selector state
  const [selectedTargetId, setSelectedTargetId] = useState<string>(
    targets[1]?.id || targets[0]?.id || ''
  );
  const [selectedProfile, setSelectedProfile] = useState<
    'QUICK_WEB' | 'WINDOWS_ENTERPRISE' | 'CUSTOM_BOUNDED'
  >('WINDOWS_ENTERPRISE');
  const [customPorts, setCustomPorts] = useState('22, 80, 443, 445, 3389, 5985, 8443');

  // Results & Feedback state
  const [portResults, setPortResults] = useState<NetworkPortResult[]>([]);
  const [latestRun, setLatestRun] = useState<AssessmentRun | null>(null);
  const [lastRunTimestamp, setLastRunTimestamp] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanMessage, setScanMessage] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const selectedTarget = targets.find((t) => t.id === selectedTargetId);

  // Quick Live Network Scan Handler
  const handleQuickNetworkScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMessage(null);
    setScanMessage(null);

    const trimmed = quickTargetHost.trim();
    if (!trimmed) {
      setErrorMessage('Please enter a target hostname, domain, or IP address (e.g. scanme.nmap.org or 192.168.1.50).');
      return;
    }

    const cleanHost = trimmed.replace(/^[a-zA-Z]+:\/\//, '').split('/')[0].split(':')[0];
    const ssrfCheck = validateTargetSsrfGuard(cleanHost, labTargetsAllowed, true);
    if (!ssrfCheck.allowed) {
      setErrorMessage(`SSRF Guard Blocked Target: ${ssrfCheck.blockedReason}`);
      return;
    }

    setIsScanning(true);
    try {
      const res = await assessmentsService.scanNetworkTarget(
        cleanHost,
        quickProfile,
        quickProfile === 'CUSTOM_BOUNDED' ? quickCustomPorts : undefined,
        user?.email
      );

      if (res.data) {
        const { run, portResults: results } = res.data;
        if (results && Array.isArray(results)) {
          setPortResults(results);
        }
        if (run) {
          setLatestRun(run);
          addAssessmentRun(run);
        }
        setLastRunTimestamp(new Date().toISOString());
        await recheckBackendConnection();

        const openCount = results?.filter((p) => p.state === 'open').length || 0;
        const criticalHigh = results?.filter((p) => p.state === 'open' && (p.risk_level === 'Critical' || p.risk_level === 'High')).length || 0;

        setScanMessage(
          `Live TCP port discovery completed for ${cleanHost}: ${openCount} Open, ${results?.length || 0} Total Scanned. ${criticalHigh > 0 ? `Alert: ${criticalHigh} Critical/High service(s) exposed!` : 'No high-risk exposures detected.'}`
        );
      }
    } catch (err: any) {
      setErrorMessage(`Network Assessment Failed: ${err?.message || 'Host connection error'}`);
    } finally {
      setIsScanning(false);
    }
  };

  // Run Assessment on Selected Authorized Target
  const handleRunAuthorizedAssessment = async () => {
    setErrorMessage(null);
    setScanMessage(null);

    if (!can('assessments:run')) {
      setErrorMessage('RBAC Restriction: VIEWER role is read-only and cannot trigger network assessments.');
      return;
    }

    if (!selectedTarget) {
      setErrorMessage('Please select a target from the allowlist first.');
      return;
    }

    if (selectedTarget.verification_status !== 'VERIFIED' || !selectedTarget.allowlisted) {
      setErrorMessage(
        `Target '${selectedTarget.target_value}' is currently ${selectedTarget.verification_status}. Complete ownership verification before running a network assessment.`
      );
      return;
    }

    setIsScanning(true);
    try {
      const res = await assessmentsService.runNetworkAssessment(
        selectedTarget.id,
        selectedProfile,
        selectedProfile === 'CUSTOM_BOUNDED' ? customPorts : undefined,
        user?.email
      );

      if (res.data) {
        const { run, portResults: results } = res.data;
        if (results && Array.isArray(results)) {
          setPortResults(results);
        }
        if (run) {
          setLatestRun(run);
          addAssessmentRun(run);
        }
        setLastRunTimestamp(new Date().toISOString());
        await recheckBackendConnection();

        const openCount = results?.filter((p) => p.state === 'open').length || 0;
        const criticalHigh = results?.filter((p) => p.state === 'open' && (p.risk_level === 'Critical' || p.risk_level === 'High')).length || 0;

        setScanMessage(
          `Bounded network assessment completed for ${selectedTarget.target_value}: ${openCount} Open, ${results?.length || 0} Total Scanned. Security Score: ${run?.risk_score || 85}/100.`
        );
      }
    } catch (err: any) {
      setErrorMessage(`Network Assessment Failed: ${err?.message || 'Server connection error'}`);
    } finally {
      setIsScanning(false);
    }
  };

  // KPI Calculations
  const openPortsList = portResults.filter((p) => p.state === 'open');
  const openCount = openPortsList.length;
  const filteredCount = portResults.filter((p) => p.state === 'filtered').length;
  const closedCount = portResults.filter((p) => p.state === 'closed').length;
  const criticalHighOpen = openPortsList.filter(
    (p) => p.risk_level === 'Critical' || p.risk_level === 'High'
  );
  const newlyOpenedCount = portResults.filter(
    (p) => p.change_since_last_scan === 'newly_opened'
  ).length;

  const currentScore = latestRun?.risk_score ?? (criticalHighOpen.length > 0 ? 55 : 92);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight flex items-center gap-2">
            <Network className="w-6 h-6 text-[#D6AE45]" />
            Authorized Network Assessment
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Bounded, allowlisted TCP port reachability, non-destructive banner inspection, and historical baseline diffing
          </p>
        </div>
        <StatusBadge status="ALLOWLIST ENFORCED" />
      </div>

      <AuthorizationBanner scopeNote="Operates strictly on verified domains and IP ranges in the organization's authorized_targets allowlist. Ad-hoc scanning of unregistered third-party domains, loopback (127.0.0.0/8), and cloud metadata (169.254.169.254) is unconditionally blocked." />

      {/* Quick Live Network Assessment Bar */}
      <Card
        title="Quick Live Network Host Discovery"
        subtitle="Enter any authorized domain, host, or lab IP to immediately probe bounded TCP reachability and grab service banners."
      >
        <form onSubmit={handleQuickNetworkScan} className="space-y-3">
          <div className="flex flex-col sm:flex-row items-center gap-3">
            <div className="relative flex-1 w-full">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#A7B0BC]" />
              <input
                type="text"
                placeholder="e.g. portal.myx-defense-demo.org or api.myx-defense-demo.org"
                value={quickTargetHost}
                onChange={(e) => setQuickTargetHost(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
              />
            </div>

            <div className="flex items-center gap-2 w-full sm:w-auto">
              <select
                aria-label="Scan Profile"
                value={quickProfile}
                onChange={(e) =>
                  setQuickProfile(
                    e.target.value as 'QUICK_WEB' | 'WINDOWS_ENTERPRISE' | 'CUSTOM_BOUNDED'
                  )
                }
                className="bg-[#101318] border border-[#29313B] text-xs font-mono text-[#F5F7FA] px-3 py-2 rounded-lg focus:outline-none focus:border-[#D6AE45]"
              >
                <option value="QUICK_WEB">Quick Web & Infra (6 Ports)</option>
                <option value="WINDOWS_ENTERPRISE">Windows Enterprise (18 Ports)</option>
                <option value="CUSTOM_BOUNDED">Custom Port List</option>
              </select>

              <Button
                type="submit"
                variant="primary"
                disabled={isScanning || !can('assessments:run')}
                icon={
                  isScanning ? (
                    <Loader2 className="w-4 h-4 animate-spin text-[#0B0D10]" />
                  ) : (
                    <Play className="w-4 h-4" />
                  )
                }
                className="w-full sm:w-auto shrink-0"
              >
                {isScanning ? 'Probing Ports...' : 'Scan Host Now'}
              </Button>
            </div>
          </div>

          {quickProfile === 'CUSTOM_BOUNDED' && (
            <div>
              <label htmlFor="quick-custom-ports" className="block text-[11px] font-medium text-[#A7B0BC] mb-1">
                Approved Comma-Separated TCP Ports (Max 100)
              </label>
              <input
                id="quick-custom-ports"
                type="text"
                value={quickCustomPorts}
                onChange={(e) => setQuickCustomPorts(e.target.value)}
                placeholder="21, 22, 80, 443, 3389, 8080"
                className="w-full px-3 py-1.5 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F5F7FA]"
              />
            </div>
          )}

          <div className="flex flex-wrap items-center justify-between text-[11px] text-[#A7B0BC] gap-2 pt-1">
            <span>Non-destructive TCP connect probes · Safe 750ms timeout · Automatic banner grabbing</span>
            <span className="font-mono text-[#38BDF8]">Protected by SSRFGuard & RFC 1918 Policy</span>
          </div>
        </form>
      </Card>

      {errorMessage && <ErrorState message={errorMessage} />}

      {scanMessage && (
        <div className="p-3.5 bg-[#38BDF8]/10 border border-[#38BDF8]/30 rounded-lg flex items-center gap-2.5 text-xs text-[#38BDF8]">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{scanMessage}</span>
        </div>
      )}

      {/* Summary KPI Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="p-4 bg-[#101318] border border-[#29313B] rounded-lg">
          <div className="text-[11px] font-medium text-[#A7B0BC] flex items-center justify-between">
            <span>Security Posture</span>
            <Activity className="w-3.5 h-3.5 text-[#38BDF8]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span
              className={`text-2xl font-bold font-mono ${
                currentScore >= 80 ? 'text-[#22C55E]' : currentScore >= 60 ? 'text-[#F59E0B]' : 'text-[#F05252]'
              }`}
            >
              {currentScore}
            </span>
            <span className="text-xs text-[#737E8C]">/ 100</span>
          </div>
          <div className="text-[11px] text-[#A7B0BC] mt-1">
            {currentScore >= 80 ? 'Low Exposure Risk' : 'Remediation Advised'}
          </div>
        </div>

        <div className="p-4 bg-[#101318] border border-[#29313B] rounded-lg">
          <div className="text-[11px] font-medium text-[#A7B0BC] flex items-center justify-between">
            <span>Open Services</span>
            <Server className="w-3.5 h-3.5 text-[#22C55E]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold font-mono text-[#22C55E]">{openCount}</span>
            <span className="text-xs text-[#737E8C]">/ {portResults.length} audited</span>
          </div>
          <div className="text-[11px] text-[#A7B0BC] mt-1 truncate">
            {openPortsList.map((p) => p.port).join(', ') || 'None active'}
          </div>
        </div>

        <div className="p-4 bg-[#101318] border border-[#29313B] rounded-lg">
          <div className="text-[11px] font-medium text-[#A7B0BC] flex items-center justify-between">
            <span>High/Critical Exposures</span>
            <AlertTriangle className="w-3.5 h-3.5 text-[#F05252]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span
              className={`text-2xl font-bold font-mono ${
                criticalHighOpen.length > 0 ? 'text-[#F05252]' : 'text-[#22C55E]'
              }`}
            >
              {criticalHighOpen.length}
            </span>
            <span className="text-xs text-[#737E8C]">critical ports</span>
          </div>
          <div className="text-[11px] text-[#A7B0BC] mt-1">
            {criticalHighOpen.length > 0 ? 'Exposed SMB / RDP / DB' : 'No critical ports open'}
          </div>
        </div>

        <div className="p-4 bg-[#101318] border border-[#29313B] rounded-lg">
          <div className="text-[11px] font-medium text-[#A7B0BC] flex items-center justify-between">
            <span>Historical Diff</span>
            <Layers className="w-3.5 h-3.5 text-[#D6AE45]" />
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span
              className={`text-2xl font-bold font-mono ${
                newlyOpenedCount > 0 ? 'text-[#F05252]' : 'text-[#A7B0BC]'
              }`}
            >
              +{newlyOpenedCount}
            </span>
            <span className="text-xs text-[#737E8C]">newly opened</span>
          </div>
          <div className="text-[11px] text-[#A7B0BC] mt-1">
            {filteredCount} filtered · {closedCount} closed
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Assessment Profile & Target Selector */}
        <Card
          title="1. Assessment Profile & Allowlist Target Selector"
          subtitle="Select a verified asset and choose a bounded TCP connect profile (Max 100 ports per run)"
          className="lg:col-span-2"
        >
          <div className="space-y-4">
            <TargetSelector
              targets={targets}
              selectedTargetId={selectedTargetId}
              onChange={setSelectedTargetId}
            />

            {selectedTarget && selectedTarget.verification_status !== 'VERIFIED' && (
              <div className="p-3.5 bg-[#F59E0B]/10 border border-[#F59E0B]/30 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
                <div className="space-y-1">
                  <div className="font-semibold text-[#F59E0B]">
                    Ownership Verification Pending ({selectedTarget.verification_method})
                  </div>
                  <div className="font-mono text-[#A7B0BC]">
                    Token: {selectedTarget.verification_token}
                  </div>
                </div>
                {can('targets:manage') && (
                  <Button
                    variant="secondary"
                    size="sm"
                    icon={<ShieldCheck className="w-3.5 h-3.5 text-[#22C55E]" />}
                    onClick={() => {
                      verifyTarget(
                        selectedTarget.id,
                        user?.email || 'midhun.krishnan@myx-security.io'
                      );
                      setScanMessage(`Ownership verified for target ${selectedTarget.target_value}.`);
                    }}
                  >
                    Verify Ownership Now
                  </Button>
                )}
              </div>
            )}

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
                  6 Ports (22, 53, 80, 443, 8080, 8443)
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
                Last Run Timestamp: {lastRunTimestamp}
              </div>
              <Button
                variant="primary"
                icon={
                  isScanning ? (
                    <Loader2 className="w-4 h-4 animate-spin text-[#0B0D10]" />
                  ) : (
                    <Play className="w-4 h-4" />
                  )
                }
                disabled={
                  isScanning ||
                  !can('assessments:run') ||
                  selectedTarget?.verification_status !== 'VERIFIED'
                }
                onClick={handleRunAuthorizedAssessment}
              >
                {isScanning ? 'Executing Network Scan...' : 'Run Bounded Network Assessment'}
              </Button>
            </div>
          </div>
        </Card>

        {/* Organization Target Allowlist */}
        <Card
          title="2. Organization Target Allowlist"
          subtitle="Active authorized_targets ledger"
        >
          <div className="space-y-2.5 max-h-[380px] overflow-y-auto pr-1">
            {targets.map((t) => (
              <div
                key={t.id}
                className={`p-3 border rounded-lg space-y-1.5 transition-colors ${
                  t.id === selectedTargetId
                    ? 'bg-[#1B222B] border-[#D6AE45]/50'
                    : 'bg-[#101318] border-[#29313B]'
                }`}
              >
                <div className="flex items-center justify-between gap-2">
                  <span
                    onClick={() => setSelectedTargetId(t.id)}
                    className="text-xs font-mono text-[#F5F7FA] truncate cursor-pointer hover:text-[#38BDF8]"
                  >
                    {t.target_value}
                  </span>
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
                        onClick={() =>
                          verifyTarget(
                            t.id,
                            user?.email || 'midhun.krishnan@myx-security.io'
                          )
                        }
                        className="text-[#22C55E] hover:underline font-medium"
                      >
                        Approve
                      </button>
                    )}
                    {can('targets:manage') && (
                      <button
                        type="button"
                        aria-label={`Remove target ${t.target_value}`}
                        onClick={() =>
                          deleteTarget(
                            t.id,
                            user?.email || 'midhun.krishnan@myx-security.io'
                          )
                        }
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
        title={`TCP Port Discovery & Historical State Comparison — ${
          selectedTarget?.target_value || quickTargetHost || 'Target Asset'
        }`}
        subtitle="Highlights newly opened services (such as exposed SMB 445 or RDP 3389) since previous baseline run"
        noPadding
      >
        <div className="overflow-x-auto">
          {portResults.length === 0 ? (
            <div className="py-12 px-4 text-center space-y-2">
              <Network className="w-9 h-9 text-[#29313B] mx-auto mb-1" />
              <div className="text-sm font-semibold text-[#F5F7FA]">No Open Ports Discovered Yet</div>
              <p className="text-xs text-[#A7B0BC] max-w-sm mx-auto">
                Enter a target host or domain above and click &ldquo;Execute Live Network Scan&rdquo; to probe network ports.
              </p>
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-[#101318] border-b border-[#29313B] text-[11px] font-medium text-[#A7B0BC]">
                  <th className="py-3 px-4">Port / Proto</th>
                  <th className="py-3 px-4">Service</th>
                  <th className="py-3 px-4">State</th>
                  <th className="py-3 px-4">Historical Diff</th>
                  <th className="py-3 px-4">Observed Banner</th>
                  <th className="py-3 px-4">Risk Level</th>
                  <th className="py-3 px-4">Analyst Notes & Guidance</th>
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
                        <span className="text-[#F05252] font-semibold bg-[#F05252]/10 px-2 py-0.5 rounded border border-[#F05252]/20">
                          + NEWLY OPENED
                        </span>
                      ) : item.change_since_last_scan === 'newly_closed' ? (
                        <span className="text-[#22C55E] font-semibold bg-[#22C55E]/10 px-2 py-0.5 rounded border border-[#22C55E]/20">
                          - NEWLY CLOSED
                        </span>
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
                    <td className="py-3 px-4 text-[#A7B0BC] max-w-xs">{item.notes}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </div>
  );
};
