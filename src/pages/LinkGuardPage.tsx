import React, { useState, useEffect } from 'react';
import { Link2, Search, ShieldAlert, Info, ExternalLink, RefreshCw } from 'lucide-react';
import { analyzeUrlWithLinkGuardLexical } from '../utils/securityLogic';
import { LinkGuardAnalysisResult } from '../types/assessment.types';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';

const SAMPLE_TEST_URLS = [
  {
    label: 'Punycode Homograph + .exe',
    url: 'https://xn--pple-43d.com/auth/login-verify.exe',
  },
  {
    label: 'Known Phishing Lookalike',
    url: 'https://microsoft-login-security-verify.com/oauth2/authorize?redirect=https://evil.example',
  },
  {
    label: 'SSRF Cloud Metadata Attempt',
    url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
  },
  {
    label: 'Clean Enterprise URL',
    url: 'https://portal.myx-defense-demo.org/documentation',
  },
];

const getProviderReportUrl = (provider: string, hostname: string, normalizedUrl: string): string | null => {
  if (provider.includes('VirusTotal')) {
    return `https://www.virustotal.com/gui/domain/${encodeURIComponent(hostname)}`;
  }
  if (provider.includes('URLhaus')) {
    return `https://urlhaus.abuse.ch/browse.php?search=${encodeURIComponent(hostname)}`;
  }
  if (provider.includes('Google Safe Browsing')) {
    return `https://transparencyreport.google.com/safe-browsing/search?url=${encodeURIComponent(normalizedUrl)}`;
  }
  return null;
};

export const LinkGuardPage: React.FC = () => {
  const [urlInput, setUrlInput] = useState(
    'https://xn--pple-43d.com/auth/login-verify.exe'
  );
  const [result, setResult] = useState<LinkGuardAnalysisResult>(() =>
    analyzeUrlWithLinkGuardLexical('https://xn--pple-43d.com/auth/login-verify.exe')
  );
  const [isLoading, setIsLoading] = useState(false);

  const executeAnalysis = async (targetUrl: string) => {
    const trimmed = targetUrl.trim();
    if (!trimmed) return;
    setIsLoading(true);
    try {
      const res = await fetch('/api/v1/linkguard/inspect', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: trimmed }),
      });
      if (res.ok) {
        const data = await res.json();
        setResult(data);
      } else {
        setResult(analyzeUrlWithLinkGuardLexical(trimmed));
      }
    } catch {
      setResult(analyzeUrlWithLinkGuardLexical(trimmed));
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    executeAnalysis(urlInput);
  }, []);

  const handleAnalyze = (e: React.FormEvent) => {
    e.preventDefault();
    executeAnalysis(urlInput);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
            LinkGuard AI — Suspicious URL & Phishing Risk Analyzer
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Lexical decomposition, Punycode/IDN homograph detection, SSRF-guarded redirect tracing,
            and Threat-Intelligence enrichment
          </p>
        </div>
        <StatusBadge status={result.verdict} />
      </div>

      {/* Mandatory LinkGuard Disclaimer */}
      <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg flex items-center gap-2.5 text-xs text-[#A7B0BC]">
        <Info className="w-4 h-4 text-[#38BDF8] shrink-0" aria-hidden="true" />
        <span>
          Mandatory Notice: A &apos;No Known Threat Detected&apos; verdict indicates no matches were
          found in currently active feeds and heuristics; it does not guarantee a URL is safe.
        </span>
      </div>

      <Card
        title="Inspect URL Structure & Threat Reputation"
        subtitle="Offline lexical inspection runs with zero target network contact; optional redirect tracing enforces SafeOutboundHttpClient SSRF protection"
      >
        <form onSubmit={handleAnalyze} className="space-y-3">
          <div className="flex flex-col sm:flex-row gap-3">
            <label htmlFor="linkguard-url-input" className="sr-only">
              URL to analyze
            </label>
            <input
              id="linkguard-url-input"
              type="text"
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              className="flex-1 px-3.5 py-2.5 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs sm:text-sm font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
            />
            <Button type="submit" variant="primary" isLoading={isLoading} icon={<Search className="w-4 h-4" />}>
              Analyze URL with LinkGuard AI
            </Button>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <span className="text-xs text-[#737E8C]">Quick Presets:</span>
            {SAMPLE_TEST_URLS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => {
                  setUrlInput(preset.url);
                  executeAnalysis(preset.url);
                }}
                className="px-2.5 py-1 rounded bg-[#101318] hover:bg-[#1B222B] border border-[#29313B] text-xs text-[#A7B0BC] hover:text-[#F5F7FA] transition-colors"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </form>
      </Card>

      {/* 4-Tier Verdict & Structural Signals */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card
          title="Lexical, Homograph & SSRF Signals"
          subtitle={`Parsed Hostname: ${result.hostname}`}
          className="lg:col-span-2"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg flex justify-between">
              <span className="text-[#A7B0BC]">4-Tier Verdict</span>
              <StatusBadge status={result.verdict} />
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg flex justify-between">
              <span className="text-[#A7B0BC]">Composite Risk Score</span>
              <span className="font-mono font-bold text-[#F5F7FA] tabular-nums">
                {result.risk_score} / 100
              </span>
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg flex justify-between">
              <span className="text-[#A7B0BC]">Punycode / IDN Homograph</span>
              <span
                className={`font-mono ${
                  result.lexical_signals.is_punycode_idn ? 'text-[#F05252]' : 'text-[#22C55E]'
                }`}
              >
                {result.lexical_signals.is_punycode_idn
                  ? `DETECTED (${result.lexical_signals.decoded_idn_hostname || 'xn--'})`
                  : 'None'}
              </span>
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg flex justify-between">
              <span className="text-[#A7B0BC]">Brand Lookalike Target</span>
              <span
                className={`font-mono ${
                  result.lexical_signals.lookalike_brand_target
                    ? 'text-[#F59E0B]'
                    : 'text-[#22C55E]'
                }`}
              >
                {result.lexical_signals.lookalike_brand_target || 'None'}
              </span>
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg flex justify-between">
              <span className="text-[#A7B0BC]">Dangerous File Extension</span>
              <span
                className={`font-mono ${
                  result.lexical_signals.suspicious_extension ? 'text-[#F05252]' : 'text-[#22C55E]'
                }`}
              >
                {result.lexical_signals.suspicious_extension || 'None'}
              </span>
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg flex justify-between">
              <span className="text-[#A7B0BC]">Outbound SSRF Guard</span>
              <span
                className={`font-mono ${
                  result.lexical_signals.ssrf_blocked ? 'text-[#F05252]' : 'text-[#22C55E]'
                }`}
              >
                {result.lexical_signals.ssrf_blocked ? 'BLOCKED' : 'Passed'}
              </span>
            </div>
          </div>

          {result.lexical_signals.ssrf_block_reason && (
            <div className="mt-3 p-3 bg-[#F05252]/10 border border-[#F05252]/30 rounded-lg text-xs text-[#F05252] font-mono">
              {result.lexical_signals.ssrf_block_reason}
            </div>
          )}
        </Card>

        <Card
          title="Threat-Intelligence Feed Enrichment"
          subtitle="Live multi-vendor threat intelligence & security vendor reputation telemetry"
          headerAction={
            <Button
              size="sm"
              variant="secondary"
              isLoading={isLoading}
              icon={<RefreshCw className="w-3.5 h-3.5" />}
              onClick={() => executeAnalysis(urlInput)}
            >
              Re-scan Feeds
            </Button>
          }
        >
          <div className="space-y-3">
            {result.threat_intel_sources.map((src) => {
              const reportUrl = getProviderReportUrl(src.provider, result.hostname, result.normalized_url);
              return (
                <div
                  key={src.provider}
                  className="p-3 bg-[#101318] border border-[#29313B] rounded-lg space-y-1.5"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-semibold text-[#F5F7FA]">{src.provider}</span>
                    <div className="flex items-center gap-2">
                      <StatusBadge status={src.status} />
                      {reportUrl && (
                        <a
                          href={reportUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          title={`Open live ${src.provider} threat report`}
                          className="inline-flex items-center gap-1 text-[11px] text-[#A7B0BC] hover:text-[#D6AE45] transition-colors px-1.5 py-0.5 rounded hover:bg-[#1B222B]"
                        >
                          <ExternalLink className="w-3.5 h-3.5" />
                          <span className="hidden sm:inline">Report</span>
                        </a>
                      )}
                    </div>
                  </div>
                  <p className="text-[11px] text-[#A7B0BC] leading-relaxed">{src.details}</p>
                </div>
              );
            })}
          </div>
        </Card>
      </div>

      {/* Grounded AI Risk Explanation */}
      <Card
        title="Gemini Grounded Risk Analysis (Facts Separated from Interpretation)"
        subtitle="Structured output separating verified lexical evidence from defensive recommendations"
      >
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-4 bg-[#101318] border border-[#29313B] rounded-lg space-y-2">
            <div className="font-semibold text-[#F5F7FA]">Verified Lexical & Network Facts</div>
            <ul className="list-disc list-inside space-y-1 text-[#A7B0BC]">
              {result.ai_explanation.verified_facts.map((fact, i) => (
                <li key={i}>{fact}</li>
              ))}
            </ul>
          </div>
          <div className="p-4 bg-[#101318] border border-[#29313B] rounded-lg space-y-2">
            <div className="font-semibold text-[#F5F7FA]">AI Risk Interpretation & Action</div>
            <p className="text-[#A7B0BC] leading-relaxed">
              {result.ai_explanation.ai_risk_interpretation}
            </p>
            <div className="pt-2 border-t border-[#29313B] text-[#F5F7FA]">
              <span className="font-semibold">Defensive Action: </span>
              <span className="text-[#A7B0BC]">{result.ai_explanation.recommended_remediation}</span>
            </div>
          </div>
        </div>
      </Card>
    </div>
  );
};
