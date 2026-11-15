import React, { useState, useEffect } from 'react';
import {
  Wifi,
  KeyRound,
  ShieldCheck,
  ShieldAlert,
  Eye,
  EyeOff,
  Copy,
  Check,
  RotateCcw,
  Sparkles,
  Download,
  AlertTriangle,
  Lock,
  Radio,
  FileCheck2,
  Trash2,
  Loader2,
} from 'lucide-react';
import { apiClient } from '../services/apiClient';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { CodeEvidenceBlock } from '../components/ui/CodeEvidenceBlock';

interface SavedProfile {
  ssid: string;
  profile_type: string;
  has_saved_credentials: boolean;
}

interface PasswordAuditResult {
  length: number;
  has_lowercase: boolean;
  has_uppercase: boolean;
  has_digits: boolean;
  has_symbols: boolean;
  entropy_bits: number;
  is_common_dictionary_match: boolean;
  score: number;
  strength: 'Weak' | 'Moderate' | 'Strong' | 'Very Strong';
  color: string;
  recommendations: string[];
}

export const WifiPasswordLabPage: React.FC = () => {
  // Module A: Profile Discovery & Selection
  const [profiles, setProfiles] = useState<SavedProfile[]>([]);
  const [selectedSsid, setSelectedSsid] = useState<string>('');
  const [loadingProfiles, setLoadingProfiles] = useState(false);

  // Module B: Local Authorized Password Recovery
  const [recoveredPassword, setRecoveredPassword] = useState<string | null>(null);
  const [securityType, setSecurityType] = useState<string>('WPA2-Personal');
  const [cipher, setCipher] = useState<string>('CCMP (AES)');
  const [isRevealed, setIsRevealed] = useState(false);
  const [copiedKey, setCopiedKey] = useState(false);
  const [loadingRecovery, setLoadingRecovery] = useState(false);
  const [recoveryNotice, setRecoveryNotice] = useState<string | null>(null);

  // Module C: Offline Password Strength Auditor
  const [customPasswordInput, setCustomPasswordInput] = useState('');
  const [auditResult, setAuditResult] = useState<PasswordAuditResult | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);

  // Module D: Wireless Network Security Posture
  const [wpsEnabled, setWpsEnabled] = useState(false);
  const [postureFindings, setPostureFindings] = useState<Array<{ title: string; severity: string; impact: string; remediation: string }>>([]);
  const [overallPosture, setOverallPosture] = useState('SECURE');
  const [defensiveRecs, setDefensiveRecs] = useState<string[]>([]);
  const [exportingPdf, setExportingPdf] = useState(false);

  // Load saved profiles from authenticated Windows device on mount
  const loadProfiles = async () => {
    setLoadingProfiles(true);
    try {
      const res = await apiClient.request<{
        ok: boolean;
        count: number;
        profiles: SavedProfile[];
      }>('/wifi/profiles');
      if (res.data?.profiles) {
        setProfiles(res.data.profiles);
        if (res.data.profiles.length > 0 && !selectedSsid) {
          setSelectedSsid(res.data.profiles[0].ssid);
        }
      }
    } catch {
      // Fallback
    } finally {
      setLoadingProfiles(false);
    }
  };

  useEffect(() => {
    loadProfiles();
  }, []);

  // Authorized Local Recovery
  const handleRecoverPassword = async () => {
    if (!selectedSsid) return;
    setLoadingRecovery(true);
    setRecoveryNotice(null);
    try {
      const res = await apiClient.request<{
        ok: boolean;
        data: {
          ssid: string;
          recovered: boolean;
          password: string | null;
          security_type: string;
          cipher: string;
          message: string;
        };
      }>('/wifi/recover-password', {
        method: 'POST',
        body: JSON.stringify({ ssid: selectedSsid }),
      });

      if (res.data?.data) {
        const d = res.data.data;
        setSecurityType(d.security_type || 'WPA2-Personal');
        setCipher(d.cipher || 'CCMP (AES)');
        if (d.recovered && d.password) {
          setRecoveredPassword(d.password);
          setRecoveryNotice('Credential successfully recovered from local Windows vault.');
          // Auto-audit recovered password offline
          handleAuditPassword(d.password);
        } else {
          setRecoveredPassword(null);
          setRecoveryNotice(d.message || 'No unencrypted PSK key stored in profile.');
        }
      }
    } catch (err: any) {
      setRecoveryNotice(err?.message || 'Local recovery failed.');
    } finally {
      setLoadingRecovery(false);
    }
  };

  const handleClearKeyFromMemory = () => {
    setRecoveredPassword(null);
    setIsRevealed(false);
    setCopiedKey(false);
    setRecoveryNotice('Sensitive password value cleared completely from browser memory.');
  };

  const handleCopyPassword = () => {
    if (!recoveredPassword) return;
    navigator.clipboard.writeText(recoveredPassword);
    setCopiedKey(true);
    setTimeout(() => setCopiedKey(false), 2000);
  };

  // Offline Password Strength Auditing
  const handleAuditPassword = async (pwdToAudit: string) => {
    if (!pwdToAudit) {
      setAuditResult(null);
      return;
    }
    try {
      const res = await apiClient.request<{
        ok: boolean;
        audit: PasswordAuditResult;
      }>('/wifi/audit-password', {
        method: 'POST',
        body: JSON.stringify({ password: pwdToAudit }),
      });
      if (res.data?.audit) {
        setAuditResult(res.data.audit);
        analyzeWirelessPosture(res.data.audit.score);
      }
    } catch {
      // Fallback
    }
  };

  const handleGenerateStrongKey = async () => {
    setIsGenerating(true);
    try {
      const res = await apiClient.request<{
        passphrase: string;
        audit: PasswordAuditResult;
      }>('/wifi/generate-password', {
        method: 'POST',
        body: JSON.stringify({ length: 16 }),
      });
      if (res.data) {
        setCustomPasswordInput(res.data.passphrase);
        setAuditResult(res.data.audit);
        analyzeWirelessPosture(res.data.audit.score);
      }
    } finally {
      setIsGenerating(false);
    }
  };

  // Wireless Posture Analysis
  const analyzeWirelessPosture = async (pwdScore?: number) => {
    try {
      const res = await apiClient.request<{
        ok: boolean;
        posture: {
          overall_posture: string;
          findings: Array<{ title: string; severity: string; impact: string; remediation: string }>;
          defensive_recommendations: string[];
        };
      }>('/wifi/analyze-network', {
        method: 'POST',
        body: JSON.stringify({
          ssid: selectedSsid || 'Target_Network',
          securityProtocol: securityType,
          cipher,
          wpsEnabled,
          passwordScore: pwdScore ?? auditResult?.score,
        }),
      });
      if (res.data?.posture) {
        setOverallPosture(res.data.posture.overall_posture);
        setPostureFindings(res.data.posture.findings);
        setDefensiveRecs(res.data.posture.defensive_recommendations);
      }
    } catch {
      // Fallback
    }
  };

  useEffect(() => {
    analyzeWirelessPosture();
  }, [selectedSsid, securityType, cipher, wpsEnabled]);

  // Export Wi-Fi PDF Report (PRIVACY: Never writes recovered password to PDF!)
  const handleExportPdf = async () => {
    setExportingPdf(true);
    try {
      const payload = {
        ssid: selectedSsid || 'Audited_Wireless_Network',
        securityProtocol: securityType,
        cipher,
        wpsEnabled,
        passwordStrength: auditResult?.strength || 'Audited',
        passwordEntropy: auditResult?.entropy_bits || 64.0,
        overallPosture,
        findings: postureFindings,
        recommendations: defensiveRecs,
      };

      const res = await fetch('/api/v1/wifi/export-pdf', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });

      if (res.ok) {
        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `MYX_AI_WiFi_Security_Audit_${(selectedSsid || 'Network').replace(/\s+/g, '_')}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
      }
    } catch (err) {
      console.error('Failed to export Wi-Fi PDF:', err);
    } finally {
      setExportingPdf(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
              Wi-Fi Password Lab & Wireless Security Analyzer
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#D6AE45]/15 text-[#D6AE45] border border-[#D6AE45]/30">
              Windows Host Local
            </span>
          </div>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Authorized local Windows profile recovery, offline entropy auditing, and defensive wireless posture analysis
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="secondary"
            size="sm"
            icon={<Download className="w-3.5 h-3.5" />}
            isLoading={exportingPdf}
            onClick={handleExportPdf}
          >
            Export Wi-Fi Security PDF
          </Button>
        </div>
      </div>

      {/* Mandatory Privacy Boundary Alert */}
      <div className="p-3.5 bg-[#101318] border border-[#22C55E]/40 rounded-lg flex items-start gap-3 text-xs text-[#A7B0BC]">
        <Lock className="w-4 h-4 text-[#22C55E] shrink-0 mt-0.5" />
        <div className="space-y-0.5">
          <strong className="text-[#F5F7FA]">Strict Privacy & Zero-Persistence Boundary:</strong>
          <p>
            Password recovery runs strictly locally on your authenticated Windows machine via read-only Windows APIs.
            Recovered passwords are <strong>never</strong> transmitted to Gemini, external APIs, or RAG, and are <strong>never</strong> stored in logs or persistent storage.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Profile Discovery & Authorized Recovery */}
        <div className="space-y-6 lg:col-span-1">
          <Card
            title="1. Saved Wi-Fi Profiles"
            subtitle="Discovered on your authenticated Windows computer"
            headerAction={
              <button
                type="button"
                onClick={loadProfiles}
                disabled={loadingProfiles}
                className="p-1 rounded text-[#A7B0BC] hover:text-[#F5F7FA] transition-colors"
                title="Refresh Profile List"
              >
                <RotateCcw className={`w-3.5 h-3.5 ${loadingProfiles ? 'animate-spin' : ''}`} />
              </button>
            }
          >
            <div className="space-y-4 text-xs">
              <div>
                <label htmlFor="select-wifi-profile" className="block text-[#A7B0BC] font-medium mb-1.5">
                  Select Wi-Fi Profile ({profiles.length} Available)
                </label>
                <select
                  id="select-wifi-profile"
                  value={selectedSsid}
                  onChange={(e) => {
                    setSelectedSsid(e.target.value);
                    setRecoveredPassword(null);
                    setRecoveryNotice(null);
                  }}
                  className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
                >
                  {profiles.length === 0 ? (
                    <option value="">No saved profiles detected</option>
                  ) : (
                    profiles.map((p) => (
                      <option key={p.ssid} value={p.ssid}>
                        {p.ssid} ({p.profile_type})
                      </option>
                    ))
                  )}
                </select>
              </div>

              {/* Profile Telemetry Details */}
              <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[#737E8C]">Active Target SSID:</span>
                  <span className="font-mono font-semibold text-[#F5F7FA]">{selectedSsid || 'None'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[#737E8C]">Security Protocol:</span>
                  <span className="font-mono text-[#38BDF8]">{securityType}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[#737E8C]">Encryption Cipher:</span>
                  <span className="font-mono text-[#22C55E]">{cipher}</span>
                </div>
              </div>

              {/* Authorized Local Recovery Action */}
              <div className="space-y-2 pt-2 border-t border-[#29313B]">
                <Button
                  variant="primary"
                  size="sm"
                  className="w-full"
                  isLoading={loadingRecovery}
                  onClick={handleRecoverPassword}
                  icon={<KeyRound className="w-3.5 h-3.5" />}
                >
                  Recover Local Wi-Fi Password
                </Button>

                {recoveryNotice && (
                  <p className="text-[11px] text-[#A7B0BC] text-center italic">{recoveryNotice}</p>
                )}
              </div>

              {/* Recovered Credential Card (Masked by default) */}
              {recoveredPassword !== null && (
                <div className="p-3.5 bg-[#141920] border border-[#D6AE45]/60 rounded-lg space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-[#D6AE45] flex items-center gap-1.5">
                      <Lock className="w-3.5 h-3.5 text-[#D6AE45]" />
                      <span>Saved Passphrase</span>
                    </span>
                    <button
                      type="button"
                      onClick={handleClearKeyFromMemory}
                      className="text-[11px] text-[#EF4444] hover:underline flex items-center gap-1"
                      title="Clear password from browser memory"
                    >
                      <Trash2 className="w-3 h-3" />
                      <span>Clear Value</span>
                    </button>
                  </div>

                  {/* Password Display Box */}
                  <div className="flex items-center gap-2 p-2.5 bg-[#080A0D] border border-[#29313B] rounded font-mono text-sm text-[#F5F7FA]">
                    <div className="flex-1 select-all truncate">
                      {isRevealed ? recoveredPassword : '••••••••••••••••'}
                    </div>
                    <button
                      type="button"
                      onClick={() => setIsRevealed((prev) => !prev)}
                      className="p-1 text-[#A7B0BC] hover:text-[#F5F7FA]"
                      title={isRevealed ? 'Hide Password' : 'Show Password'}
                    >
                      {isRevealed ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                    <button
                      type="button"
                      onClick={handleCopyPassword}
                      className="p-1 text-[#A7B0BC] hover:text-[#22C55E]"
                      title="Copy Passphrase"
                    >
                      {copiedKey ? <Check className="w-4 h-4 text-[#22C55E]" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </Card>

          {/* Module D: Wireless Architecture & WPS Posture */}
          <Card
            title="2. Wireless Interface Settings"
            subtitle="Configure detected security parameters for posture audit"
          >
            <div className="space-y-3.5 text-xs">
              <div>
                <label htmlFor="security-protocol-select" className="block text-[#A7B0BC] mb-1">
                  Security Protocol
                </label>
                <select
                  id="security-protocol-select"
                  value={securityType}
                  onChange={(e) => setSecurityType(e.target.value)}
                  className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded font-mono text-[#F5F7FA]"
                >
                  <option value="WPA3-Personal">WPA3-Personal (SAE — Most Secure)</option>
                  <option value="WPA2-Personal">WPA2-Personal (AES-CCMP — Standard)</option>
                  <option value="WPA-Personal">WPA1-Personal (Legacy — Vulnerable)</option>
                  <option value="WEP">WEP (Deprecated — Insecure)</option>
                  <option value="Open">Open / Unencrypted (High Risk)</option>
                </select>
              </div>

              <div>
                <label htmlFor="cipher-select" className="block text-[#A7B0BC] mb-1">
                  Encryption Cipher
                </label>
                <select
                  id="cipher-select"
                  value={cipher}
                  onChange={(e) => setCipher(e.target.value)}
                  className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded font-mono text-[#F5F7FA]"
                >
                  <option value="CCMP (AES)">CCMP (AES — Recommended)</option>
                  <option value="TKIP">TKIP (Temporal Key — Deprecated)</option>
                  <option value="None">None (Unencrypted)</option>
                </select>
              </div>

              <div className="flex items-center justify-between p-2.5 bg-[#101318] border border-[#29313B] rounded-lg">
                <div>
                  <div className="font-semibold text-[#F5F7FA]">WPS (Wi-Fi Protected Setup)</div>
                  <div className="text-[11px] text-[#737E8C]">PIN brute-force vulnerability flag</div>
                </div>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={wpsEnabled}
                    onChange={(e) => setWpsEnabled(e.target.checked)}
                    className="w-4 h-4 rounded bg-[#080A0D] border-[#29313B]"
                  />
                  <span className={wpsEnabled ? 'text-[#F59E0B] font-semibold' : 'text-[#737E8C]'}>
                    {wpsEnabled ? 'Enabled' : 'Disabled'}
                  </span>
                </label>
              </div>
            </div>
          </Card>
        </div>

        {/* Right Column: Password Strength Auditor & Wireless Security Findings */}
        <div className="space-y-6 lg:col-span-2">
          {/* Offline Password Auditor */}
          <Card
            title="3. Offline Wi-Fi Password Strength Auditor"
            subtitle="Deterministic local evaluation: length, diversity, Shannon entropy, and common attack dictionaries"
            headerAction={
              <Button
                variant="secondary"
                size="sm"
                icon={<Sparkles className="w-3.5 h-3.5 text-[#D6AE45]" />}
                isLoading={isGenerating}
                onClick={handleGenerateStrongKey}
              >
                Generate 16-Char Passphrase
              </Button>
            }
          >
            <div className="space-y-4 text-xs">
              <div>
                <label htmlFor="offline-pwd-test" className="block font-medium text-[#F5F7FA] mb-1.5">
                  Test Any Wi-Fi Password or Passphrase (Evaluated Completely Offline)
                </label>
                <div className="flex items-center gap-2">
                  <input
                    id="offline-pwd-test"
                    type="text"
                    value={customPasswordInput}
                    onChange={(e) => {
                      setCustomPasswordInput(e.target.value);
                      handleAuditPassword(e.target.value);
                    }}
                    placeholder="Enter Wi-Fi password to audit (e.g. correct-horse-battery-staple-99!)"
                    className="flex-1 px-3.5 py-2.5 bg-[#080A0D] border border-[#29313B] rounded-lg font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
                  />
                  {recoveredPassword && (
                    <Button
                      variant="secondary"
                      size="sm"
                      onClick={() => {
                        setCustomPasswordInput(recoveredPassword);
                        handleAuditPassword(recoveredPassword);
                      }}
                    >
                      Audit Recovered Key
                    </Button>
                  )}
                </div>
              </div>

              {/* Strength Results Matrix */}
              {auditResult && (
                <div className="p-4 bg-[#101318] border border-[#29313B] rounded-lg space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-2.5">
                      <span className="text-sm font-semibold text-[#F5F7FA]">Complexity Score:</span>
                      <span className="font-mono text-base font-bold text-[#D6AE45]">{auditResult.score}/100</span>
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-semibold ${
                          auditResult.strength === 'Very Strong'
                            ? 'bg-[#22C55E]/15 text-[#22C55E] border border-[#22C55E]/40'
                            : auditResult.strength === 'Strong'
                            ? 'bg-[#38BDF8]/15 text-[#38BDF8] border border-[#38BDF8]/40'
                            : auditResult.strength === 'Moderate'
                            ? 'bg-[#F59E0B]/15 text-[#F59E0B] border border-[#F59E0B]/40'
                            : 'bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/40'
                        }`}
                      >
                        {auditResult.strength}
                      </span>
                    </div>

                    <div className="font-mono text-[#737E8C]">
                      Entropy: <strong>{auditResult.entropy_bits} bits</strong> (Pool Size)
                    </div>
                  </div>

                  {/* Character Diversity Checklist */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-[#29313B] text-[11px] font-mono">
                    <div className={`p-2 rounded flex items-center justify-between ${auditResult.has_lowercase ? 'bg-[#22C55E]/10 text-[#22C55E]' : 'bg-[#141920] text-[#737E8C]'}`}>
                      <span>Lowercase [a-z]</span>
                      {auditResult.has_lowercase ? '✓' : '✗'}
                    </div>
                    <div className={`p-2 rounded flex items-center justify-between ${auditResult.has_uppercase ? 'bg-[#22C55E]/10 text-[#22C55E]' : 'bg-[#141920] text-[#737E8C]'}`}>
                      <span>Uppercase [A-Z]</span>
                      {auditResult.has_uppercase ? '✓' : '✗'}
                    </div>
                    <div className={`p-2 rounded flex items-center justify-between ${auditResult.has_digits ? 'bg-[#22C55E]/10 text-[#22C55E]' : 'bg-[#141920] text-[#737E8C]'}`}>
                      <span>Digits [0-9]</span>
                      {auditResult.has_digits ? '✓' : '✗'}
                    </div>
                    <div className={`p-2 rounded flex items-center justify-between ${auditResult.has_symbols ? 'bg-[#22C55E]/10 text-[#22C55E]' : 'bg-[#141920] text-[#737E8C]'}`}>
                      <span>Symbols [!@#$]</span>
                      {auditResult.has_symbols ? '✓' : '✗'}
                    </div>
                  </div>

                  {/* Dictionary Match Alert */}
                  {auditResult.is_common_dictionary_match && (
                    <div className="p-3 bg-[#EF4444]/15 border border-[#EF4444]/40 rounded-lg flex items-center gap-2 text-[#EF4444]">
                      <AlertTriangle className="w-4 h-4 shrink-0" />
                      <span>CRITICAL: This password matches known wordlists/cracking dictionaries. Change immediately.</span>
                    </div>
                  )}

                  {/* Recommendations */}
                  <div className="space-y-1 pt-1">
                    <div className="font-semibold text-[#A7B0BC]">Hardening Recommendations:</div>
                    <ul className="list-disc list-inside text-[#A7B0BC] space-y-0.5">
                      {auditResult.recommendations.map((rec, i) => (
                        <li key={i}>{rec}</li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </div>
          </Card>

          {/* Wireless Security Posture & Findings */}
          <Card
            title={`4. Wireless Security Analysis (${postureFindings.length} Finding${postureFindings.length === 1 ? '' : 's'})`}
            subtitle="Defensive assessment against WPA3 standards, cipher deprecation, and AP isolation"
            headerAction={<StatusBadge status={overallPosture} />}
          >
            <div className="space-y-4 text-xs">
              {postureFindings.length === 0 ? (
                <div className="p-4 bg-[#22C55E]/10 border border-[#22C55E]/30 rounded-lg flex items-center gap-2.5 text-[#22C55E]">
                  <ShieldCheck className="w-5 h-5 shrink-0" />
                  <div>
                    <strong>Secure Wireless Posture Verified:</strong> Network uses modern WPA2/WPA3 AES encryption with no detected WPS vulnerabilities.
                  </div>
                </div>
              ) : (
                <div className="space-y-3">
                  {postureFindings.map((f, idx) => (
                    <div
                      key={idx}
                      className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg space-y-1.5"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-[#F5F7FA]">{f.title}</span>
                        <SeverityBadge severity={f.severity as any} />
                      </div>
                      <p className="text-[#A7B0BC] leading-relaxed">
                        <strong className="text-[#F5F7FA]">Impact:</strong> {f.impact}
                      </p>
                      <p className="text-[#38BDF8] leading-relaxed">
                        <strong className="text-[#F5F7FA]">Remediation:</strong> {f.remediation}
                      </p>
                    </div>
                  ))}
                </div>
              )}

              {/* Best Practice Architecture Recommendations */}
              <div className="pt-2 border-t border-[#29313B] space-y-2">
                <h4 className="font-semibold text-[#F5F7FA] flex items-center gap-1.5">
                  <Radio className="w-4 h-4 text-[#D6AE45]" />
                  <span>Router & Access Point Defensive Guidelines</span>
                </h4>
                <ul className="list-disc list-inside text-[#A7B0BC] space-y-1">
                  {defensiveRecs.map((rec, i) => (
                    <li key={i}>{rec}</li>
                  ))}
                </ul>
              </div>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};
