import React, { useState, useEffect } from 'react';
import {
  Radio,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  RefreshCw,
  Lock,
  Wifi,
  Server,
  Terminal,
  Clock,
  Sparkles,
  Sliders,
  History as HistoryIcon,
  CheckCircle2,
  XCircle,
  HelpCircle,
  Play,
  ArrowRight,
  Database,
  ExternalLink,
} from 'lucide-react';
import { networkTrustService } from '../services/networkTrust.service';
import {
  LiveNetworkTelemetry,
  NetworkProfileRecord,
  NetworkRiskAssessmentResult,
  NetworkQuarantineStatus,
  NetworkProtectionPolicyRecord,
  AiNetworkExplanationResponse,
} from '../types/network_trust.types';
import { useRBAC } from '../hooks/useRBAC';

export const NetworkTrustIntelligencePage: React.FC = () => {
  const { role, isViewer } = useRBAC();
  const [activeTab, setActiveTab] = useState<
    'overview' | 'live' | 'profiles' | 'risk' | 'quarantine' | 'policy' | 'history' | 'ai-copilot'
  >('overview');

  const [loading, setLoading] = useState<boolean>(true);
  const [telemetry, setTelemetry] = useState<LiveNetworkTelemetry | null>(null);
  const [profiles, setProfiles] = useState<NetworkProfileRecord[]>([]);
  const [currentAssessment, setCurrentAssessment] = useState<NetworkRiskAssessmentResult | null>(null);
  const [quarantineStatus, setQuarantineStatus] = useState<NetworkQuarantineStatus | null>(null);
  const [policy, setPolicy] = useState<NetworkProtectionPolicyRecord | null>(null);
  const [history, setHistory] = useState<NetworkRiskAssessmentResult[]>([]);
  
  // AI Copilot state
  const [aiExplanation, setAiExplanation] = useState<AiNetworkExplanationResponse | null>(null);
  const [aiMode, setAiMode] = useState<'beginner' | 'technical'>('beginner');
  const [aiLoading, setAiLoading] = useState<boolean>(false);

  // Quarantine action state
  const [quarantineReason, setQuarantineReason] = useState<string>('Suspicious encryption downgrade detected');
  const [actionLoading, setActionLoading] = useState<boolean>(false);
  const [statusMessage, setStatusMessage] = useState<{ text: string; type: 'success' | 'error' | 'info' } | null>(null);

  // Profile modal / form state
  const [newProfileType, setNewProfileType] = useState<'PERSONAL' | 'ORGANIZATION'>('PERSONAL');

  const loadData = async () => {
    setLoading(true);
    try {
      const [telemetryRes, profilesRes, quarantineRes, policyRes, historyRes] = await Promise.all([
        networkTrustService.getLiveTelemetry(),
        networkTrustService.getProfiles(),
        networkTrustService.getQuarantineStatus(),
        networkTrustService.getPolicies(),
        networkTrustService.getHistory(15),
      ]);

      if (telemetryRes?.data) {
        setTelemetry(telemetryRes.data);
        // Automatically run risk evaluation on live telemetry
        const evalRes = await networkTrustService.evaluateRisk({
          ssid: telemetryRes.data.ssid,
          bssid: telemetryRes.data.bssid,
          auth_type: telemetryRes.data.auth_type,
          cipher: telemetryRes.data.cipher,
          signal_quality: telemetryRes.data.signal_quality,
          gateway_ip: telemetryRes.data.gateway_ip,
          gateway_mac: telemetryRes.data.gateway_mac,
          dns_servers: telemetryRes.data.dns_servers,
          captive_portal_detected: telemetryRes.data.captive_portal_detected,
        });
        if (evalRes?.data) {
          setCurrentAssessment(evalRes.data);
        }
      }

      if (profilesRes?.data?.profiles) setProfiles(profilesRes.data.profiles);
      if (quarantineRes?.data) setQuarantineStatus(quarantineRes.data);
      if (policyRes?.data) setPolicy(policyRes.data);
      if (historyRes?.data?.history) setHistory(historyRes.data.history);
    } catch (err: any) {
      console.error('Failed to load Network Trust data', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const triggerAiExplain = async (mode: 'beginner' | 'technical') => {
    if (!currentAssessment) return;
    setAiLoading(true);
    setAiMode(mode);
    try {
      const res = await networkTrustService.getAiExplanation(currentAssessment, mode);
      if (res?.data) {
        setAiExplanation(res.data);
      }
    } catch (err: any) {
      console.error('AI explanation failed', err);
    } finally {
      setAiLoading(false);
    }
  };

  const handleApplyQuarantine = async () => {
    if (isViewer) {
      setStatusMessage({ text: "Permission Denied: 'VIEWER' role cannot apply quarantine.", type: 'error' });
      return;
    }
    setActionLoading(true);
    try {
      const res = await networkTrustService.applyQuarantine({
        reason: quarantineReason,
        risk_score: currentAssessment?.risk_score || 75,
        target_interface: telemetry?.adapter_name || 'Wi-Fi',
        timeout_seconds: policy?.watchdog_timeout_sec || 900,
        pinned_dns_ips: policy?.allowed_dns,
      });
      if (res?.data) {
        setStatusMessage({ text: res.data.message || 'Quarantine applied successfully.', type: 'success' });
        loadData();
      }
    } catch (err: any) {
      setStatusMessage({ text: err?.message || 'Quarantine failed', type: 'error' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleReleaseQuarantine = async () => {
    if (isViewer) {
      setStatusMessage({ text: "Permission Denied: 'VIEWER' role cannot release quarantine.", type: 'error' });
      return;
    }
    setActionLoading(true);
    try {
      const res = await networkTrustService.releaseQuarantine();
      if (res?.data) {
        setStatusMessage({ text: res.data.message || 'Quarantine released cleanly.', type: 'success' });
        loadData();
      }
    } catch (err: any) {
      setStatusMessage({ text: err?.message || 'Release failed', type: 'error' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleSaveAsProfile = async () => {
    if (!telemetry || isViewer) return;
    setActionLoading(true);
    try {
      const res = await networkTrustService.createProfile({
        ssid: telemetry.ssid,
        profile_type: newProfileType,
        auth_type: telemetry.auth_type,
        cipher: telemetry.cipher,
        gateway_ip: telemetry.gateway_ip,
        gateway_mac: telemetry.gateway_mac,
        dns_servers: telemetry.dns_servers,
        baseline_bssids: [telemetry.bssid],
      });
      if (res?.data) {
        setStatusMessage({ text: `Network profile '${telemetry.ssid}' saved as ${newProfileType}.`, type: 'success' });
        loadData();
      }
    } catch (err: any) {
      setStatusMessage({ text: err?.message || 'Failed to save profile', type: 'error' });
    } finally {
      setActionLoading(false);
    }
  };

  const handleApproveProfile = async (profileId: string) => {
    if (isViewer) return;
    try {
      await networkTrustService.approveProfile(profileId);
      setStatusMessage({ text: 'Profile approved.', type: 'success' });
      loadData();
    } catch (err: any) {
      setStatusMessage({ text: err?.message || 'Approval failed', type: 'error' });
    }
  };

  const getSeverityBadgeClass = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-500/20 text-red-400 border border-red-500/30';
      case 'HIGH':
        return 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
      case 'MODERATE':
        return 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30';
      default:
        return 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Banner & Quick Context */}
      <div className="p-6 rounded-2xl bg-zinc-900 border border-zinc-800 shadow-xl flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center shrink-0">
            <Radio className="w-7 h-7 text-emerald-400 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-2xl font-bold tracking-tight text-zinc-100">
                Network Trust Intelligence
              </h1>
              <span className="px-2 py-0.5 rounded text-xs font-mono font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                BALANCED MODE
              </span>
            </div>
            <p className="text-sm text-zinc-400 mt-1">
              Deterministic 802.11 & Layer 3 drift detection, continuous profile verification & scoped Windows Firewall containment.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          {quarantineStatus?.is_quarantined ? (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-red-500/20 border border-red-500/40 text-red-300 font-mono text-xs animate-pulse">
              <ShieldAlert className="w-4 h-4 text-red-400" />
              <span>QUARANTINE ACTIVE</span>
              <button
                onClick={handleReleaseQuarantine}
                disabled={actionLoading || isViewer}
                className="ml-2 px-2 py-1 rounded bg-red-600 hover:bg-red-500 text-white font-sans text-xs font-bold transition disabled:opacity-50"
              >
                Emergency Release
              </button>
            </div>
          ) : (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-zinc-300 font-mono text-xs">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>FIREWALL NORMAL</span>
            </div>
          )}

          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Rescan</span>
          </button>
        </div>
      </div>

      {/* Global Status Message Toast */}
      {statusMessage && (
        <div
          className={`p-4 rounded-xl text-sm flex items-center justify-between border ${
            statusMessage.type === 'error'
              ? 'bg-red-950/60 text-red-300 border-red-800'
              : statusMessage.type === 'success'
              ? 'bg-emerald-950/60 text-emerald-300 border-emerald-800'
              : 'bg-zinc-800 text-zinc-200 border-zinc-700'
          }`}
        >
          <span>{statusMessage.text}</span>
          <button onClick={() => setStatusMessage(null)} className="text-zinc-400 hover:text-zinc-100 text-xs ml-4">
            Dismiss
          </button>
        </div>
      )}

      {/* Location Permission Alert for Windows 11 (24H2) */}
      {telemetry?.location_permission_required && (
        <div className="p-4 rounded-xl bg-amber-950/40 border border-amber-800/60 text-amber-300 text-xs flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 shrink-0 text-amber-400" />
          <div>
            <span className="font-semibold">Windows 11 WLAN Privacy Notice: </span>
            Windows Location Permission is required to enumerate visible BSSID MACs. Enable{' '}
            <span className="font-mono bg-zinc-900 px-1 py-0.5 rounded">Settings &gt; Privacy &amp; security &gt; Location &gt; Let desktop apps access your location</span>.
          </div>
        </div>
      )}

      {/* Tab Navigation */}
      <div className="flex border-b border-zinc-800 gap-1 overflow-x-auto pb-1">
        {[
          { id: 'overview', label: 'Overview', icon: <Radio className="w-4 h-4" /> },
          { id: 'live', label: 'Live Monitor', icon: <Wifi className="w-4 h-4" /> },
          { id: 'profiles', label: 'Network Profiles', icon: <Database className="w-4 h-4" /> },
          { id: 'risk', label: 'Risk & Diff Engine', icon: <ShieldAlert className="w-4 h-4" /> },
          { id: 'quarantine', label: 'Quarantine Center', icon: <Lock className="w-4 h-4" /> },
          { id: 'policy', label: 'Protection Policies', icon: <Sliders className="w-4 h-4" /> },
          { id: 'history', label: 'Event History', icon: <HistoryIcon className="w-4 h-4" /> },
          { id: 'ai-copilot', label: 'AI Incident Copilot', icon: <Sparkles className="w-4 h-4" /> },
        ].map((tab) => (
          <button
            key={tab.id}
            onClick={() => {
              setActiveTab(tab.id as any);
              if (tab.id === 'ai-copilot' && !aiExplanation) {
                triggerAiExplain('beginner');
              }
            }}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition whitespace-nowrap ${
              activeTab === tab.id
                ? 'bg-zinc-800 text-emerald-400 border border-zinc-700 shadow-sm'
                : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50'
            }`}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* TAB 1: OVERVIEW */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {/* Metric 1: Current SSID */}
            <div className="p-5 rounded-xl bg-zinc-900 border border-zinc-800">
              <span className="text-xs text-zinc-400 uppercase tracking-wider font-semibold">Active Wi-Fi Connection</span>
              <div className="text-xl font-bold text-zinc-100 mt-2 truncate">
                {telemetry?.ssid || 'Scanning...'}
              </div>
              <div className="text-xs text-zinc-500 font-mono mt-1 truncate">
                BSSID: {telemetry?.bssid || 'N/A'}
              </div>
            </div>

            {/* Metric 2: Deterministic Risk Score */}
            <div className="p-5 rounded-xl bg-zinc-900 border border-zinc-800">
              <span className="text-xs text-zinc-400 uppercase tracking-wider font-semibold">Evaluated Risk Score</span>
              <div className="flex items-center gap-3 mt-2">
                <span className="text-3xl font-extrabold text-zinc-100">
                  {currentAssessment?.risk_score ?? 0}
                  <span className="text-sm font-normal text-zinc-500">/100</span>
                </span>
                <span className={`px-2 py-0.5 rounded text-xs font-bold ${getSeverityBadgeClass(currentAssessment?.severity || 'LOW')}`}>
                  {currentAssessment?.severity || 'LOW'}
                </span>
              </div>
              <div className="text-xs text-zinc-500 mt-1">Confidence: {currentAssessment?.confidence ?? 100}%</div>
            </div>

            {/* Metric 3: Encryption Suite */}
            <div className="p-5 rounded-xl bg-zinc-900 border border-zinc-800">
              <span className="text-xs text-zinc-400 uppercase tracking-wider font-semibold">Security Protocol</span>
              <div className="text-lg font-bold text-zinc-100 mt-2 truncate">
                {telemetry?.auth_type || 'WPA2-Personal'}
              </div>
              <div className="text-xs text-zinc-500 font-mono mt-1">Cipher: {telemetry?.cipher || 'CCMP'}</div>
            </div>

            {/* Metric 4: Balanced Protection Action */}
            <div className="p-5 rounded-xl bg-zinc-900 border border-zinc-800">
              <span className="text-xs text-zinc-400 uppercase tracking-wider font-semibold">Recommended Action</span>
              <div className="text-sm font-semibold text-zinc-200 mt-2">
                {currentAssessment?.quarantine_action === 'NONE'
                  ? 'Continuous Monitoring'
                  : currentAssessment?.quarantine_action === 'NOTIFY_USER'
                  ? 'User Verification Recommended'
                  : currentAssessment?.quarantine_action === 'SELECTIVE_RESTRICTION'
                  ? 'Selective Route Restriction'
                  : 'Scoped Firewall Quarantine'}
              </div>
              <div className="text-xs text-zinc-500 mt-1">Mode: Balanced</div>
            </div>
          </div>

          {/* Detailed Summary Card */}
          <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800">
            <h3 className="text-base font-bold text-zinc-100 flex items-center gap-2">
              <Shield className="w-5 h-5 text-emerald-400" />
              <span>Posture Assessment &amp; Drift Summary</span>
            </h3>
            <p className="text-sm text-zinc-300 mt-2">
              {currentAssessment?.explanation || 'Network characteristics match baseline policy.'}
            </p>

            <div className="mt-4 pt-4 border-t border-zinc-800 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-xs text-zinc-400">
                <span>Default Gateway:</span>
                <span className="font-mono text-zinc-200">{telemetry?.gateway_ip} ({telemetry?.gateway_mac})</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setActiveTab('risk')}
                  className="px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 text-xs font-medium transition flex items-center gap-1.5"
                >
                  <span>Inspect Risk Rules</span>
                  <ArrowRight className="w-3.5 h-3.5" />
                </button>
                <button
                  onClick={() => setActiveTab('ai-copilot')}
                  className="px-3 py-1.5 rounded-lg bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 text-xs font-medium transition flex items-center gap-1.5"
                >
                  <Sparkles className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Explain with AI Copilot</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 2: LIVE MONITOR */}
      {activeTab === 'live' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Layer 2: 802.11 Wireless Details */}
            <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 space-y-4">
              <h3 className="text-base font-bold text-zinc-100 flex items-center gap-2">
                <Wifi className="w-5 h-5 text-emerald-400" />
                <span>Layer 2: 802.11 Wireless Telemetry</span>
              </h3>

              <div className="space-y-3 text-sm">
                <div className="flex justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">Adapter Interface</span>
                  <span className="font-mono text-zinc-200">{telemetry?.adapter_name || 'Wi-Fi'}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">SSID</span>
                  <span className="font-bold text-zinc-100">{telemetry?.ssid}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">Connected BSSID (MAC)</span>
                  <span className="font-mono text-zinc-200">{telemetry?.bssid}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">Authentication Protocol</span>
                  <span className="font-mono text-zinc-200">{telemetry?.auth_type}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">Pairwise Cipher</span>
                  <span className="font-mono text-zinc-200">{telemetry?.cipher}</span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-zinc-400">Signal Quality</span>
                  <span className="font-bold text-emerald-400">{telemetry?.signal_quality}%</span>
                </div>
              </div>
            </div>

            {/* Layer 3: IP, Gateway & DNS Details */}
            <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 space-y-4">
              <h3 className="text-base font-bold text-zinc-100 flex items-center gap-2">
                <Server className="w-5 h-5 text-emerald-400" />
                <span>Layer 3: IP, Gateway &amp; Resolver Telemetry</span>
              </h3>

              <div className="space-y-3 text-sm">
                <div className="flex justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">Default Gateway IP</span>
                  <span className="font-mono text-zinc-200">{telemetry?.gateway_ip}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">Gateway Hardware MAC (ARP)</span>
                  <span className="font-mono text-zinc-200">{telemetry?.gateway_mac}</span>
                </div>
                <div className="flex justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">DNS Resolvers</span>
                  <span className="font-mono text-zinc-200">
                    {telemetry?.dns_servers?.join(', ') || '1.1.1.1'}
                  </span>
                </div>
                <div className="flex justify-between py-2 border-b border-zinc-800">
                  <span className="text-zinc-400">Captive Portal Status</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${telemetry?.captive_portal_detected ? 'bg-amber-500/20 text-amber-300' : 'bg-emerald-500/20 text-emerald-300'}`}>
                    {telemetry?.captive_portal_detected ? 'Redirect Detected' : 'No Captive Portal'}
                  </span>
                </div>
                <div className="flex justify-between py-2">
                  <span className="text-zinc-400">Deterministic Fingerprint</span>
                  <span className="font-mono text-xs text-zinc-400 truncate max-w-[200px]" title={telemetry?.calculated_fingerprint}>
                    {telemetry?.calculated_fingerprint?.slice(0, 16)}...
                  </span>
                </div>
              </div>

              <div className="pt-3 border-t border-zinc-800 flex items-center gap-3">
                <select
                  value={newProfileType}
                  onChange={(e) => setNewProfileType(e.target.value as any)}
                  className="px-2.5 py-1.5 rounded-lg bg-zinc-800 border border-zinc-700 text-xs text-zinc-200"
                >
                  <option value="PERSONAL">Save as Personal Profile</option>
                  <option value="ORGANIZATION">Save as Enterprise Profile</option>
                </select>
                <button
                  onClick={handleSaveAsProfile}
                  disabled={actionLoading || isViewer}
                  className="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition disabled:opacity-50"
                >
                  Save as Trusted Baseline
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 3: NETWORK PROFILES */}
      {activeTab === 'profiles' && (
        <div className="space-y-6">
          <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-base font-bold text-zinc-100">Known &amp; Trusted Network Profiles</h3>
                <p className="text-xs text-zinc-400 mt-0.5">
                  Baselines for personal users and enterprise organizations. Strict tenant isolation enforced.
                </p>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-zinc-300">
                <thead className="bg-zinc-800 text-xs uppercase text-zinc-400 border-b border-zinc-700">
                  <tr>
                    <th className="px-4 py-3">SSID</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Approval Status</th>
                    <th className="px-4 py-3">Auth / Cipher</th>
                    <th className="px-4 py-3">Gateway MAC</th>
                    <th className="px-4 py-3">Approved By</th>
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {profiles.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="px-4 py-6 text-center text-zinc-500 text-xs">
                        No network profiles registered yet. Connect to a network and click 'Save as Trusted Baseline'.
                      </td>
                    </tr>
                  ) : (
                    profiles.map((p) => (
                      <tr key={p.id} className="hover:bg-zinc-800/40 transition">
                        <td className="px-4 py-3 font-semibold text-zinc-100">{p.ssid}</td>
                        <td className="px-4 py-3 font-mono text-xs">
                          <span className={`px-2 py-0.5 rounded ${p.profile_type === 'ORGANIZATION' ? 'bg-indigo-500/20 text-indigo-300' : 'bg-zinc-800 text-zinc-300'}`}>
                            {p.profile_type}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs font-semibold ${p.status === 'APPROVED' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                            {p.status}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs font-mono">{p.baseline_auth} ({p.baseline_cipher})</td>
                        <td className="px-4 py-3 text-xs font-mono">{p.baseline_gateway_mac || 'Any'}</td>
                        <td className="px-4 py-3 text-xs text-zinc-400">{p.approved_by || 'Unapproved'}</td>
                        <td className="px-4 py-3 text-right">
                          {p.status !== 'APPROVED' && !isViewer && (
                            <button
                              onClick={() => handleApproveProfile(p.id)}
                              className="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition"
                            >
                              Approve
                            </button>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 4: RISK & DIFF ENGINE */}
      {activeTab === 'risk' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 md:col-span-1 space-y-4">
              <h3 className="text-base font-bold text-zinc-100">Deterministic Engine Scoring</h3>
              <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800 text-center">
                <span className="text-4xl font-extrabold text-zinc-100">
                  {currentAssessment?.risk_score ?? 0}
                </span>
                <span className="text-zinc-500 text-sm"> / 100</span>
                <div className="mt-2">
                  <span className={`px-2.5 py-1 rounded text-xs font-bold ${getSeverityBadgeClass(currentAssessment?.severity || 'LOW')}`}>
                    {currentAssessment?.severity || 'LOW'} SEVERITY
                  </span>
                </div>
                <div className="text-xs text-zinc-400 mt-3">Confidence Rating: {currentAssessment?.confidence}%</div>
              </div>

              <div className="text-xs text-zinc-400 leading-relaxed space-y-2">
                <p>
                  <strong>Zero-LLM Authoritative Rule:</strong> Risk score is evaluated using deterministic mathematical rule weights (NTI-R01 to NTI-R10).
                </p>
                <p>
                  Missing telemetry (e.g., hidden SSID or blocked ARP) reduces confidence and incurs an uncertainty penalty—it never defaults to safe.
                </p>
              </div>
            </div>

            <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 md:col-span-2 space-y-4">
              <h3 className="text-base font-bold text-zinc-100">Triggered Security Rules &amp; Signals</h3>
              {(!currentAssessment?.detected_signals || currentAssessment.detected_signals.length === 0) ? (
                <div className="p-6 rounded-xl bg-zinc-950/60 border border-zinc-800 text-center text-zinc-400 text-xs">
                  <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                  All 10 security rules passed. No active crypto downgrade, rogue AP, or ARP drift detected.
                </div>
              ) : (
                <div className="space-y-2">
                  {currentAssessment.detected_signals.map((sig, idx) => (
                    <div key={idx} className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 flex items-start gap-3">
                      <span className="px-2 py-0.5 rounded font-mono text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
                        {sig.rule_id}
                      </span>
                      <div className="flex-1">
                        <div className="flex justify-between items-center">
                          <span className="text-sm font-semibold text-zinc-200">{sig.name}</span>
                          <span className="text-xs font-bold text-red-400">+{sig.penalty} pts</span>
                        </div>
                        <p className="text-xs text-zinc-400 mt-1">{sig.explanation}</p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Field-Level Differences Table */}
          <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800">
            <h3 className="text-base font-bold text-zinc-100 mb-2">Field-Level Baseline Differences</h3>
            <p className="text-xs text-zinc-400 mb-4">
              Direct comparison between approved baseline profile and current live connection.
            </p>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-zinc-300">
                <thead className="bg-zinc-800 text-xs uppercase text-zinc-400 border-b border-zinc-700">
                  <tr>
                    <th className="px-4 py-2.5">Field</th>
                    <th className="px-4 py-2.5">Baseline Value</th>
                    <th className="px-4 py-2.5">Observed Value</th>
                    <th className="px-4 py-2.5">Drift Classification</th>
                    <th className="px-4 py-2.5">Explanation</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {(!currentAssessment?.field_diffs || currentAssessment.field_diffs.length === 0) ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-4 text-center text-zinc-500 text-xs">
                        No field differences detected. Connection matches approved baseline.
                      </td>
                    </tr>
                  ) : (
                    currentAssessment.field_diffs.map((diff, i) => (
                      <tr key={i}>
                        <td className="px-4 py-2.5 font-mono text-xs font-bold text-zinc-200">{diff.field}</td>
                        <td className="px-4 py-2.5 font-mono text-xs text-zinc-400">{JSON.stringify(diff.baseline)}</td>
                        <td className="px-4 py-2.5 font-mono text-xs text-amber-300">{JSON.stringify(diff.observed)}</td>
                        <td className="px-4 py-2.5 text-xs">
                          <span className={`px-2 py-0.5 rounded font-mono ${diff.drift_category === 'BENIGN_ROAMING' ? 'bg-blue-500/20 text-blue-300' : 'bg-red-500/20 text-red-300'}`}>
                            {diff.drift_category}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-xs text-zinc-300">{diff.explanation}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 5: QUARANTINE CENTER */}
      {activeTab === 'quarantine' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Control Panel */}
            <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 space-y-4">
              <h3 className="text-base font-bold text-zinc-100 flex items-center gap-2">
                <Lock className="w-5 h-5 text-emerald-400" />
                <span>Scoped Windows Firewall Containment</span>
              </h3>
              <p className="text-xs text-zinc-400 leading-relaxed">
                Applies bounded outbound blocks strictly to the wireless interface (<code>MYX_AI_NTI_*</code>).
                Ethernet, VPN adapters, and local loopback are untouched. Existing Windows Firewall policy is never disabled or overwritten.
              </p>

              <div className="space-y-3 pt-2">
                <div>
                  <label className="text-xs font-medium text-zinc-400">Trigger Reason</label>
                  <input
                    type="text"
                    value={quarantineReason}
                    onChange={(e) => setQuarantineReason(e.target.value)}
                    className="w-full mt-1 px-3 py-2 rounded-lg bg-zinc-800 border border-zinc-700 text-sm text-zinc-200"
                    placeholder="e.g. Rogue AP detected"
                  />
                </div>

                <div className="flex items-center gap-3 pt-2">
                  <button
                    onClick={handleApplyQuarantine}
                    disabled={actionLoading || quarantineStatus?.is_quarantined || isViewer}
                    className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-semibold text-xs transition disabled:opacity-50"
                  >
                    Enforce Scoped Quarantine
                  </button>
                  <button
                    onClick={handleReleaseQuarantine}
                    disabled={actionLoading || !quarantineStatus?.is_quarantined || isViewer}
                    className="px-4 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-700 text-zinc-200 font-semibold text-xs transition disabled:opacity-50"
                  >
                    Emergency Rollback
                  </button>
                </div>
              </div>
            </div>

            {/* Quarantine Safety & Rule Inspector */}
            <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 space-y-4">
              <h3 className="text-base font-bold text-zinc-100">Isolation Safety &amp; Persistent Watchdog</h3>

              <div className="space-y-2 text-xs">
                <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 flex justify-between">
                  <span className="text-zinc-400">Loopback Exemption (127.0.0.1 / ::1)</span>
                  <span className="text-emerald-400 font-bold">Unconditionally Allowed</span>
                </div>
                <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 flex justify-between">
                  <span className="text-zinc-400">Local DHCP (UDP 67/68 to Gateway)</span>
                  <span className="text-emerald-400 font-bold">Lease Maintained</span>
                </div>
                <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 flex justify-between">
                  <span className="text-zinc-400">Pinned DNS Resolvers (UDP/TCP 53)</span>
                  <span className="font-mono text-zinc-200">1.1.1.1, 9.9.9.9</span>
                </div>
                <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 flex justify-between">
                  <span className="text-zinc-400">Persistent Watchdog</span>
                  <span className="text-emerald-400 font-bold">Task Scheduler (schtasks.exe)</span>
                </div>
                <div className="p-3 rounded-lg bg-zinc-950 border border-zinc-800 flex justify-between">
                  <span className="text-zinc-400">Disk State File</span>
                  <span className="font-mono text-zinc-300">C:\ProgramData\MYX_AI\quarantine_state.json</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* TAB 6: POLICY MANAGEMENT */}
      {activeTab === 'policy' && (
        <div className="space-y-6">
          <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 space-y-4">
            <h3 className="text-base font-bold text-zinc-100">Balanced Protection Mode Policy</h3>
            <p className="text-xs text-zinc-400">
              Configure risk score thresholds, pinned DNS resolvers, and watchdog failsafe durations.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 text-sm">
              <div className="p-4 rounded-lg bg-zinc-950 border border-zinc-800">
                <span className="text-xs text-zinc-400">Low Severity Max Threshold</span>
                <div className="text-lg font-bold text-emerald-400 mt-1">{policy?.low_threshold || 24}</div>
                <span className="text-xs text-zinc-500">Normal operations; passive monitoring</span>
              </div>
              <div className="p-4 rounded-lg bg-zinc-950 border border-zinc-800">
                <span className="text-xs text-zinc-400">Moderate Severity Max Threshold</span>
                <div className="text-lg font-bold text-yellow-400 mt-1">{policy?.moderate_threshold || 49}</div>
                <span className="text-xs text-zinc-500">Anomaly detected; notify user and verify</span>
              </div>
              <div className="p-4 rounded-lg bg-zinc-950 border border-zinc-800">
                <span className="text-xs text-zinc-400">High Severity Max Threshold</span>
                <div className="text-lg font-bold text-amber-400 mt-1">{policy?.high_threshold || 74}</div>
                <span className="text-xs text-zinc-500">High-confidence threat; apply selective restrictions</span>
              </div>
              <div className="p-4 rounded-lg bg-zinc-950 border border-zinc-800">
                <span className="text-xs text-zinc-400">Critical Severity Min Threshold</span>
                <div className="text-lg font-bold text-red-400 mt-1">{policy?.critical_threshold || 75}</div>
                <span className="text-xs text-zinc-500">Severe threat; enforce scoped quarantine</span>
              </div>
            </div>

            <div className="p-4 rounded-lg bg-zinc-950 border border-zinc-800">
              <span className="text-xs font-semibold text-zinc-400">Pinned Trusted DNS Allowlist</span>
              <div className="font-mono text-xs text-zinc-200 mt-1">
                {policy?.allowed_dns?.join(', ') || '1.1.1.1, 9.9.9.9, 8.8.8.8'}
              </div>
              <span className="text-xs text-zinc-500 mt-1 block">
                During quarantine, plain port 53 DNS is restricted to these pinned resolvers to eliminate DNS poisoning and tunneling.
              </span>
            </div>
          </div>
        </div>
      )}

      {/* TAB 7: EVENT HISTORY */}
      {activeTab === 'history' && (
        <div className="space-y-6">
          <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800">
            <h3 className="text-base font-bold text-zinc-100 mb-4">Historical Network Risk Assessments</h3>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm text-zinc-300">
                <thead className="bg-zinc-800 text-xs uppercase text-zinc-400 border-b border-zinc-700">
                  <tr>
                    <th className="px-4 py-3">Timestamp</th>
                    <th className="px-4 py-3">Score</th>
                    <th className="px-4 py-3">Severity</th>
                    <th className="px-4 py-3">Confidence</th>
                    <th className="px-4 py-3">Detected Signals</th>
                    <th className="px-4 py-3">Recommended Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {history.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-6 text-center text-zinc-500 text-xs">
                        No historical network events recorded yet.
                      </td>
                    </tr>
                  ) : (
                    history.map((h, i) => (
                      <tr key={i} className="hover:bg-zinc-800/40 transition">
                        <td className="px-4 py-3 font-mono text-xs text-zinc-400">
                          {new Date(h.assessed_at).toLocaleString()}
                        </td>
                        <td className="px-4 py-3 font-bold text-zinc-100">{h.risk_score}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-xs font-semibold ${getSeverityBadgeClass(h.severity)}`}>
                            {h.severity}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs font-mono">{h.confidence}%</td>
                        <td className="px-4 py-3 text-xs">
                          {h.detected_signals?.map((s) => s.rule_id).join(', ') || 'None'}
                        </td>
                        <td className="px-4 py-3 text-xs text-zinc-300">{h.recommended_action}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* TAB 8: AI INCIDENT COPILOT */}
      {activeTab === 'ai-copilot' && (
        <div className="space-y-6">
          <div className="p-6 rounded-xl bg-zinc-900 border border-zinc-800 space-y-4">
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
              <div>
                <h3 className="text-base font-bold text-zinc-100 flex items-center gap-2">
                  <Sparkles className="w-5 h-5 text-emerald-400" />
                  <span>AI Incident Copilot (Gemini RAG Grounded)</span>
                </h3>
                <p className="text-xs text-zinc-400 mt-0.5">
                  Strictly separates verified technical evidence from AI interpretation. AI explains drift; it does not set risk scores.
                </p>
              </div>

              {/* Mode Toggle */}
              <div className="flex items-center gap-1 p-1 bg-zinc-950 rounded-lg border border-zinc-800">
                <button
                  onClick={() => triggerAiExplain('beginner')}
                  className={`px-3 py-1 rounded text-xs font-medium transition ${
                    aiMode === 'beginner' ? 'bg-zinc-800 text-emerald-300 font-bold' : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  Beginner-Friendly
                </button>
                <button
                  onClick={() => triggerAiExplain('technical')}
                  className={`px-3 py-1 rounded text-xs font-medium transition ${
                    aiMode === 'technical' ? 'bg-zinc-800 text-emerald-300 font-bold' : 'text-zinc-400 hover:text-zinc-200'
                  }`}
                >
                  Technical Analysis
                </button>
              </div>
            </div>

            {aiLoading ? (
              <div className="p-8 text-center text-zinc-400 text-sm flex flex-col items-center gap-2">
                <RefreshCw className="w-6 h-6 animate-spin text-emerald-400" />
                <span>Generating grounded explanation with Gemini AI...</span>
              </div>
            ) : aiExplanation ? (
              <div className="space-y-4 pt-2">
                <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800">
                  <h4 className="text-sm font-bold text-zinc-200 mb-1">{aiExplanation.overview}</h4>
                  <p className="text-xs text-zinc-300 leading-relaxed">
                    {aiExplanation.what_happened || 'Assessment complete.'}
                  </p>
                </div>

                {aiMode === 'beginner' ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800">
                      <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">What Could Happen</span>
                      <p className="text-xs text-zinc-300 mt-2 leading-relaxed">
                        {aiExplanation.real_world_impact}
                      </p>
                    </div>
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800">
                      <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Recommended Steps</span>
                      <ul className="text-xs text-zinc-300 mt-2 space-y-1.5 list-disc list-inside">
                        {aiExplanation.recommended_steps?.map((step, sIdx) => (
                          <li key={sIdx}>{step}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800">
                      <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Relevant Security Standards</span>
                      <ul className="text-xs text-zinc-300 mt-2 space-y-1 list-disc list-inside">
                        {aiExplanation.security_standards_relevance?.map((std, idx) => (
                          <li key={idx} className="font-mono">{std}</li>
                        ))}
                      </ul>
                    </div>
                    <div className="p-4 rounded-xl bg-zinc-950 border border-zinc-800">
                      <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Technical Remediation</span>
                      <ul className="text-xs text-zinc-300 mt-2 space-y-1.5 list-disc list-inside">
                        {aiExplanation.remediation_instructions?.map((rem, rIdx) => (
                          <li key={rIdx}>{rem}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            ) : null}
          </div>
        </div>
      )}
    </div>
  );
};
