import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import {
  Globe,
  Play,
  PlusCircle,
  ShieldCheck,
  CheckCircle2,
  Loader2,
  Activity,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Layers,
  Download,
} from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { useAuth } from '../hooks/useAuth';
import { useRBAC } from '../hooks/useRBAC';
import { validateTargetSsrfGuard } from '../utils/securityLogic';
import { assessmentsService } from '../services/assessments.service';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { StatusBadge } from '../components/ui/StatusBadge';
import { CodeEvidenceBlock } from '../components/ui/CodeEvidenceBlock';
import { TargetSelector } from '../components/common/TargetSelector';
import { AuthorizationBanner } from '../components/common/AuthorizationBanner';
import { ErrorState } from '../components/ui/States';
import { TargetEnvironment, VerificationMethod, AssessmentRun } from '../types/assessment.types';

export const WebsiteAssessmentPage: React.FC = () => {
  const {
    targets,
    registerTarget,
    verifyTarget,
    assessments,
    addAssessmentRun,
    labTargetsAllowed,
    recheckBackendConnection,
  } = useSystemStatus();
  const { user } = useAuth();
  const { can } = useRBAC();

  const webTargets = targets.filter((t) => t.target_type === 'URL' || t.target_type === 'DOMAIN');
  const [selectedTargetId, setSelectedTargetId] = useState<string>(webTargets[0]?.id || '');

  // Keep selectedTargetId synced when targets load or change
  useEffect(() => {
    if ((!selectedTargetId || !webTargets.some((t) => t.id === selectedTargetId)) && webTargets.length > 0) {
      setSelectedTargetId(webTargets[0].id);
    }
  }, [webTargets, selectedTargetId]);

  // Quick Live Website URL Assessment state
  const [quickScanUrl, setQuickScanUrl] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [liveScanResult, setLiveScanResult] = useState<AssessmentRun | null>(null);

  // New Target Registration state
  const [newUrlValue, setNewUrlValue] = useState('');
  const [newDisplayName, setNewDisplayName] = useState('');
  const [newEnv, setNewEnv] = useState<TargetEnvironment>('PRODUCTION');
  const [newMethod, setNewMethod] = useState<VerificationMethod>('DNS_TXT');
  const [legalAttested, setLegalAttested] = useState(false);
  const [registrationError, setRegistrationError] = useState<string | null>(null);
  const [scanMessage, setScanMessage] = useState<string | null>(null);

  const selectedTarget = targets.find((t) => t.id === selectedTargetId);

  // Derive the active assessment run to display:
  // If a live scan was performed, show that live scan result.
  // If an error occurred, do NOT fall back to demo data.
  // Only if no scan has run and no error exists, show selected target's previous run if any.
  const latestWebsiteRun: AssessmentRun | null =
    liveScanResult ||
    (registrationError
      ? null
      : selectedTargetId
      ? assessments.find((a) => a.module_type === 'WEBSITE' && a.target_id === selectedTargetId) || null
      : null);

  // Quick Live Website Scan Handler
  const handleQuickScan = async (e: React.FormEvent) => {
    e.preventDefault();
    setRegistrationError(null);
    setScanMessage(null);

    const trimmed = quickScanUrl.trim();
    if (!trimmed) {
      setRegistrationError('Please enter a website URL or domain to scan (e.g., https://example.com).');
      return;
    }

    const formatted = trimmed.startsWith('http://') || trimmed.startsWith('https://')
      ? trimmed
      : `https://${trimmed}`;

    const ssrfCheck = validateTargetSsrfGuard(formatted, labTargetsAllowed, true);
    if (!ssrfCheck.allowed) {
      setLiveScanResult(null);
      setRegistrationError(`SSRF Guard Blocked Target: ${ssrfCheck.blockedReason}`);
      return;
    }

    setIsScanning(true);
    try {
      const res = await assessmentsService.scanWebsiteUrl(formatted, user?.email);
      if (res.data && res.data.run) {
        const runData = res.data.run;
        addAssessmentRun(runData);
        setLiveScanResult(runData);
        await recheckBackendConnection();
        setScanMessage(
          `Live assessment completed for ${runData.target_display}! Security Score: ${runData.risk_score}/100 · ${runData.summary.failed} Failed, ${runData.summary.warnings} Warnings, ${runData.summary.passed} Passed.`
        );
      } else {
        setLiveScanResult(null);
        setRegistrationError('Scan returned an empty or malformed response from the backend.');
      }
    } catch (err: any) {
      setLiveScanResult(null);
      setRegistrationError(`Scan Failed: ${err?.message || 'Network connection failed'}`);
    } finally {
      setIsScanning(false);
    }
  };

  // Run Assessment on Selected Authorized Target
  const handleRunWebsiteAssessment = async () => {
    setRegistrationError(null);
    setScanMessage(null);

    if (!can('assessments:run')) {
      setRegistrationError('RBAC Restriction: VIEWER role is read-only and cannot trigger assessments.');
      return;
    }

    if (!selectedTarget || !selectedTarget.target_value || !selectedTarget.target_value.trim()) {
      setRegistrationError('Target value cannot be empty. Select or register a valid target with a non-empty target URL first.');
      return;
    }

    if (selectedTarget.verification_status !== 'VERIFIED' || !selectedTarget.allowlisted) {
      setRegistrationError(
        `Target '${selectedTarget.target_value}' is currently ${selectedTarget.verification_status}. Complete ownership verification before running a website assessment.`
      );
      return;
    }

    let canonicalUrl = selectedTarget.target_value.trim();
    if (!canonicalUrl.startsWith('http://') && !canonicalUrl.startsWith('https://')) {
      canonicalUrl = `https://${canonicalUrl}`;
    }

    const ssrfCheck = validateTargetSsrfGuard(canonicalUrl, labTargetsAllowed, true);
    if (!ssrfCheck.allowed) {
      setLiveScanResult(null);
      setRegistrationError(`SSRF Guard Blocked Target: ${ssrfCheck.blockedReason}`);
      return;
    }

    setIsScanning(true);
    try {
      const res = await assessmentsService.runWebsiteAssessment(
        selectedTarget.id,
        canonicalUrl,
        user?.email
      );

      if (res.data && res.data.run) {
        const runData = res.data.run;
        addAssessmentRun(runData);
        setLiveScanResult(runData);
        await recheckBackendConnection();
        setScanMessage(
          `${runData.is_demo_preview ? '[DEMO PREVIEW]' : '[LIVE SCAN]'} Assessment completed for ${runData.target_display}! Security Score: ${runData.risk_score}/100 · ${runData.summary.failed} Failed, ${runData.summary.warnings} Warnings, ${runData.summary.passed} Passed.`
        );
      } else {
        setLiveScanResult(null);
        setRegistrationError('Backend did not return valid assessment run data.');
      }
    } catch (err: any) {
      setLiveScanResult(null);
      setRegistrationError(`Assessment Failed: ${err?.message || 'Server connection error'}`);
    } finally {
      setIsScanning(false);
    }
  };

  // Register New Target Handler
  const handleRegisterTarget = (e: React.FormEvent) => {
    e.preventDefault();
    setRegistrationError(null);

    if (!can('targets:manage')) {
      setRegistrationError('RBAC Permission Denied: VIEWER role cannot register targets.');
      return;
    }

    if (!newUrlValue.trim() || !newDisplayName.trim()) {
      setRegistrationError('Please provide both a valid Target URL/Domain and Display Name.');
      return;
    }

    if (!legalAttested) {
      setRegistrationError(
        'Mandatory Control: You must attest legal ownership or written authorization before registering a target.'
      );
      return;
    }

    const ssrfResult = validateTargetSsrfGuard(
      newUrlValue,
      labTargetsAllowed,
      newMethod === 'ADMIN_LAB_APPROVAL'
    );

    if (!ssrfResult.allowed) {
      setRegistrationError(`SSRF & Allowlist Guard Blocked Target: ${ssrfResult.blockedReason}`);
      return;
    }

    const created = registerTarget({
      target_type: newUrlValue.includes('://') ? 'URL' : 'DOMAIN',
      target_value: newUrlValue.trim(),
      display_name: newDisplayName.trim(),
      environment: newEnv,
      verification_method: newMethod,
      attestation_notes: 'Attested ownership via Website Assessment registration workflow.',
      actor_email: user?.email || 'midhun.krishnan@myx-security.io',
    });

    setSelectedTargetId(created.id);
    setNewUrlValue('');
    setNewDisplayName('');
    setLegalAttested(false);
    setScanMessage(
      `Target '${created.target_value}' registered with status ${created.verification_status}.`
    );
  };

  // Dynamic Header Status Badge logic
  const headerStatus = registrationError
    ? 'SCAN FAILED'
    : liveScanResult
    ? liveScanResult.is_demo_preview
      ? 'DEMO / SAMPLE PREVIEW MODE'
      : 'LIVE ASSESSMENT ACTIVE'
    : latestWebsiteRun && !latestWebsiteRun.is_demo_preview
    ? 'LIVE ASSESSMENT ACTIVE'
    : latestWebsiteRun?.is_demo_preview
    ? 'DEMO / SAMPLE PREVIEW MODE'
    : 'LIVE AUDIT READY';

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight flex items-center gap-2">
            <Globe className="w-6 h-6 text-[#D6AE45]" />
            Website Security Assessment
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Non-destructive HTTP/HTTPS security headers, CSP, HSTS, Set-Cookie flags, redirect chain
            validation, and server banner exposure
          </p>
        </div>
        <StatusBadge status={headerStatus} />
      </div>

      <AuthorizationBanner scopeNote="Passive HTTP header, cookie, and TLS configuration inspection only. Never sends SQLi, XSS, fuzzing payloads, or DoS traffic. Note: Passive header analysis does not replace authenticated DAST or source code review." />

      {/* Quick Live Website Assessment Bar */}
      <Card
        title="Quick Live Website Security Assessment"
        subtitle="Enter any live website URL or domain to immediately scan HTTP security headers, CSP, HSTS, clickjacking, and server exposure."
      >
        <form onSubmit={handleQuickScan} className="space-y-3">
          <div className="flex flex-col sm:flex-row items-center gap-3">
            <div className="relative flex-1 w-full">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#A7B0BC]" />
              <input
                type="text"
                placeholder="e.g. https://example.com or https://github.com"
                value={quickScanUrl}
                onChange={(e) => setQuickScanUrl(e.target.value)}
                className="w-full pl-9 pr-3 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
              />
            </div>
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
              {isScanning ? 'Scanning Website...' : 'Scan Website Now'}
            </Button>
          </div>
          <div className="flex flex-wrap items-center justify-between text-[11px] text-[#A7B0BC] gap-2 pt-1">
            <span>
              Real-time passive audit: Content-Security-Policy · HSTS · X-Frame-Options · X-Content-Type-Options · Server Banners · Referrer-Policy
            </span>
            <span className="font-mono text-[#38BDF8]">
              SafeOutboundClient (10s Timeout · Follows Redirects · SSRF Guard)
            </span>
          </div>
        </form>
      </Card>

      {registrationError && (
        <ErrorState
          title="Website Assessment Failed"
          message={registrationError}
          onRetry={() => {
            setRegistrationError(null);
            if (quickScanUrl.trim()) {
              handleQuickScan({ preventDefault: () => {} } as any);
            }
          }}
        />
      )}

      {scanMessage && (
        <div className="p-4 bg-[#38BDF8]/10 border border-[#38BDF8]/30 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-[#38BDF8]">
          <div className="flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 shrink-0 text-[#38BDF8]" />
            <span className="font-medium text-[#F5F7FA]">{scanMessage}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Link
              to="/reports"
              className="px-3 py-1.5 bg-[#D6AE45] hover:bg-[#E7C66A] text-[#080A0D] rounded-md font-semibold text-xs transition-colors"
            >
              View Report
            </Link>
            <Link
              to="/findings"
              className="px-3 py-1.5 bg-[#101318] hover:bg-[#1B222B] text-[#F5F7FA] border border-[#29313B] rounded-md font-medium text-xs transition-colors"
            >
              Inspect Findings
            </Link>
            <Link
              to="/ai/analyst"
              className="px-3 py-1.5 bg-[#101318] hover:bg-[#1B222B] text-[#38BDF8] border border-[#38BDF8]/30 rounded-md font-medium text-xs transition-colors"
            >
              AI Copilot
            </Link>
          </div>
        </div>
      )}

      {/* Summary KPI Cards if a valid run exists */}
      {latestWebsiteRun && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          <div className="p-4 bg-[#101318] border border-[#29313B] rounded-lg">
            <div className="text-[11px] font-medium text-[#A7B0BC] flex items-center justify-between">
              <span>Security Score</span>
              <Activity className="w-3.5 h-3.5 text-[#38BDF8]" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span
                className={`text-2xl font-bold font-mono ${
                  (latestWebsiteRun.risk_score ?? 0) >= 80
                    ? 'text-[#22C55E]'
                    : (latestWebsiteRun.risk_score ?? 0) >= 50
                    ? 'text-[#F59E0B]'
                    : 'text-[#EF4444]'
                }`}
              >
                {latestWebsiteRun.risk_score ?? 0}
              </span>
              <span className="text-xs text-[#737E8C]">/ 100</span>
            </div>
            <div className="text-[11px] text-[#A7B0BC] mt-1">
              {(latestWebsiteRun.risk_score ?? 0) >= 80
                ? 'Strong Header Posture'
                : (latestWebsiteRun.risk_score ?? 0) >= 50
                ? 'Moderate Deficiencies'
                : 'High Risk Configuration'}
            </div>
          </div>

          <div className="p-4 bg-[#101318] border border-[#29313B] rounded-lg">
            <div className="text-[11px] font-medium text-[#A7B0BC] flex items-center justify-between">
              <span>Passed Controls</span>
              <CheckCircle className="w-3.5 h-3.5 text-[#22C55E]" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-[#22C55E]">
                {latestWebsiteRun.summary?.passed ?? 0}
              </span>
              <span className="text-xs text-[#737E8C]">
                / {latestWebsiteRun.summary?.total_checks ?? (latestWebsiteRun.results?.length || 0)} checks
              </span>
            </div>
            <div className="text-[11px] text-[#A7B0BC] mt-1">Properly Enforced Headers</div>
          </div>

          <div className="p-4 bg-[#101318] border border-[#29313B] rounded-lg">
            <div className="text-[11px] font-medium text-[#A7B0BC] flex items-center justify-between">
              <span>Warnings</span>
              <AlertTriangle className="w-3.5 h-3.5 text-[#F59E0B]" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono text-[#F59E0B]">
                {latestWebsiteRun.summary?.warnings ?? 0}
              </span>
              <span className="text-xs text-[#737E8C]">warnings</span>
            </div>
            <div className="text-[11px] text-[#A7B0BC] mt-1">Permissive or Sub-optimal</div>
          </div>

          <div className="p-4 bg-[#101318] border border-[#29313B] rounded-lg">
            <div className="text-[11px] font-medium text-[#A7B0BC] flex items-center justify-between">
              <span>Failed Controls</span>
              <XCircle className="w-3.5 h-3.5 text-[#EF4444]" />
            </div>
            <div className="mt-2 flex items-baseline gap-2">
              <span
                className={`text-2xl font-bold font-mono ${
                  (latestWebsiteRun.summary?.failed ?? 0) > 0 ? 'text-[#EF4444]' : 'text-[#22C55E]'
                }`}
              >
                {latestWebsiteRun.summary?.failed ?? 0}
              </span>
              <span className="text-xs text-[#737E8C]">missing headers</span>
            </div>
            <div className="text-[11px] text-[#A7B0BC] mt-1">High Severity Exposures</div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Run Assessment on Verified Target */}
        <Card
          title="1. Select Verified Target & Execute Check"
          subtitle="Pre-flight check enforces authorized_targets allowlist & SSRF DNS rebinding guard"
          className="lg:col-span-2"
        >
          <div className="space-y-4">
            <TargetSelector
              targets={webTargets}
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
                      verifyTarget(selectedTarget.id, user?.email || 'midhun.krishnan@myx-security.io');
                      setScanMessage(`Ownership verified for ${selectedTarget.target_value}.`);
                    }}
                  >
                    Verify Ownership Now
                  </Button>
                )}
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[#29313B]">
              <div className="text-xs text-[#A7B0BC]">
                Outbound Client: <span className="font-mono text-[#F5F7FA]">SafeOutboundHttpClient</span>{' '}
                (Max 5 Redirects · 10s Timeout · IP Pinning)
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
                onClick={handleRunWebsiteAssessment}
              >
                {isScanning ? 'Executing Passive Audit...' : 'Run Passive Website Assessment'}
              </Button>
            </div>
          </div>
        </Card>

        {/* Register New Target */}
        <Card
          title="2. Register New Authorized Target"
          subtitle="DNS TXT, HTTP .well-known, or Admin Lab Approval"
        >
          <form onSubmit={handleRegisterTarget} className="space-y-3">
            <div>
              <label htmlFor="new-web-url" className="block text-xs font-medium text-[#F5F7FA] mb-1">
                Target URL or Domain
              </label>
              <input
                id="new-web-url"
                type="text"
                placeholder="https://app.example.com"
                value={newUrlValue}
                onChange={(e) => setNewUrlValue(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
              />
            </div>

            <div>
              <label htmlFor="new-web-name" className="block text-xs font-medium text-[#F5F7FA] mb-1">
                Asset Display Name
              </label>
              <input
                id="new-web-name"
                type="text"
                placeholder="Production Customer App"
                value={newDisplayName}
                onChange={(e) => setNewDisplayName(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
              />
            </div>

            <div className="grid grid-cols-2 gap-2">
              <div>
                <label htmlFor="new-web-env" className="block text-xs font-medium text-[#F5F7FA] mb-1">
                  Environment
                </label>
                <select
                  id="new-web-env"
                  value={newEnv}
                  onChange={(e) => setNewEnv(e.target.value as TargetEnvironment)}
                  className="w-full px-2.5 py-1.5 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs text-[#F5F7FA]"
                >
                  <option value="PRODUCTION">PRODUCTION</option>
                  <option value="STAGING">STAGING</option>
                  <option value="LAB">LAB</option>
                </select>
              </div>
              <div>
                <label htmlFor="new-web-method" className="block text-xs font-medium text-[#F5F7FA] mb-1">
                  Verification
                </label>
                <select
                  id="new-web-method"
                  value={newMethod}
                  onChange={(e) => setNewMethod(e.target.value as VerificationMethod)}
                  className="w-full px-2.5 py-1.5 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs text-[#F5F7FA]"
                >
                  <option value="DNS_TXT">DNS TXT Token</option>
                  <option value="HTTP_FILE">HTTP /.well-known</option>
                  <option value="ADMIN_LAB_APPROVAL">Admin Lab Approval</option>
                </select>
              </div>
            </div>

            <label className="flex items-start gap-2 text-xs text-[#A7B0BC] cursor-pointer">
              <input
                type="checkbox"
                checked={legalAttested}
                onChange={(e) => setLegalAttested(e.target.checked)}
                className="mt-0.5 rounded border-[#29313B]"
              />
              <span>
                I attest that I own or hold explicit written legal authorization to assess this
                target.
              </span>
            </label>

            <Button
              type="submit"
              variant="secondary"
              size="sm"
              icon={<PlusCircle className="w-3.5 h-3.5" />}
              className="w-full"
              disabled={!can('targets:manage')}
            >
              Register & Generate Token
            </Button>
          </form>
        </Card>
      </div>

      {/* Assessment Check Results */}
      {!latestWebsiteRun ? (
        <Card
          title="Live Assessment Evidence & Control Findings"
          subtitle="Waiting for scan execution"
        >
          <div className="py-12 px-4 text-center space-y-2">
            <Globe className="w-10 h-10 text-[#737E8C]/50 mx-auto mb-2" />
            <h3 className="text-sm font-semibold text-[#F5F7FA]">No Website Scan Executed Yet</h3>
            <p className="text-xs text-[#A7B0BC] max-w-md mx-auto">
              Enter any website URL in the quick scan bar above and click{' '}
              <strong>Scan Website Now</strong> to inspect live HTTP headers, CSP, HSTS, and clickjacking defenses.
            </p>
          </div>
        </Card>
      ) : (
        <Card
          title={`Inspected Controls — ${latestWebsiteRun.target_display}`}
          subtitle={
            latestWebsiteRun.is_demo_preview
              ? 'Sample Baseline Data — Baseline simulation for offline sample target'
              : 'Live Real-Time HTTP Security Header & TLS Configuration Evidence'
          }
          headerAction={
            <div className="flex flex-wrap items-center gap-2.5">
              {latestWebsiteRun.is_demo_preview ? (
                <span className="px-2.5 py-0.5 rounded text-[11px] font-semibold bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/30 font-mono">
                  DEMO / SAMPLE PREVIEW
                </span>
              ) : (
                <span className="px-2.5 py-0.5 rounded text-[11px] font-semibold bg-[#22C55E]/15 text-[#22C55E] border border-[#22C55E]/30 font-mono">
                  LIVE SCAN RESULT
                </span>
              )}
              <div className="flex items-center gap-1.5">
                <span className="text-xs text-[#A7B0BC]">Score:</span>
                <span
                  className={`px-2.5 py-0.5 rounded text-xs font-bold font-mono border ${
                    (latestWebsiteRun.risk_score ?? 0) >= 80
                      ? 'text-[#22C55E] bg-[#22C55E]/10 border-[#22C55E]/30'
                      : (latestWebsiteRun.risk_score ?? 0) >= 50
                      ? 'text-[#F59E0B] bg-[#F59E0B]/10 border-[#F59E0B]/30'
                      : 'text-[#EF4444] bg-[#EF4444]/10 border-[#EF4444]/30'
                  }`}
                >
                  {latestWebsiteRun.risk_score ?? 0}/100
                </span>
              </div>
              <Button
                variant="secondary"
                size="sm"
                icon={<Download className="w-3.5 h-3.5 text-[#D6AE45]" />}
                onClick={async () => {
                  try {
                    await assessmentsService.downloadAssessmentPdf(
                      latestWebsiteRun.id,
                      `MYX-Report-${latestWebsiteRun.id}.pdf`
                    );
                  } catch (err: any) {
                    setRegistrationError(`PDF Download failed: ${err?.message || 'Error generating PDF'}`);
                  }
                }}
              >
                Download PDF Report
              </Button>
            </div>
          }
        >
          <div className="space-y-4">
            {(latestWebsiteRun.results || []).map((check, idx) => (
              <div
                key={check.id || check.control_id || check.check_code || `check-${idx}`}
                className="p-4 bg-[#101318] border border-[#29313B] rounded-lg space-y-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-xs text-[#38BDF8]">{check.check_code || check.control_id}</span>
                    <h3 className="text-sm font-semibold text-[#F5F7FA]">{check.check_title}</h3>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-[#A7B0BC]">
                      Confidence: {check.confidence || 'Confirmed'}
                    </span>
                    <SeverityBadge severity={check.severity || 'Informational'} />
                    <StatusBadge status={check.status || 'INFO'} />
                  </div>
                </div>

                <CodeEvidenceBlock
                  title={`Sanitized HTTP Header Evidence (${check.category || 'General'})`}
                  code={check.raw_evidence || check.actual_header_observed || '(No evidence recorded)'}
                  language="http"
                  secretsRedacted
                />

                <div className="text-xs text-[#A7B0BC]">
                  <span className="font-semibold text-[#F5F7FA]">Defensive Remediation: </span>
                  {check.remediation_text || check.remediation_recommendation || 'No remediation required.'}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
};
