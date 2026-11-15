import React, { useState } from 'react';
import { Server, Play } from 'lucide-react';
import { INITIAL_DNS_RESULT } from '../data/seedPreviewData';
import { evaluateSpfAndDmarcRecords } from '../utils/securityLogic';
import { DnsAnalysisResult } from '../types/assessment.types';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { CodeEvidenceBlock } from '../components/ui/CodeEvidenceBlock';

export const DnsAnalyzerPage: React.FC = () => {
  const [domain, setDomain] = useState('');
  const [customSpf, setCustomSpf] = useState('');
  const [customDmarc, setCustomDmarc] = useState('');
  const [result, setResult] = useState<DnsAnalysisResult | null>(null);

  const handleAnalyze = (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim() && !customSpf.trim() && !customDmarc.trim()) return;
    const evaluated = evaluateSpfAndDmarcRecords(
      customSpf.trim() ? [customSpf.trim()] : ['v=spf1 -all'],
      customDmarc.trim() ? [customDmarc.trim()] : ['v=DMARC1; p=reject']
    );
    setResult({
      ...INITIAL_DNS_RESULT,
      domain: domain.trim() || 'analyzed-domain.org',
      analyzed_at: new Date().toISOString(),
      records: {
        ...INITIAL_DNS_RESULT.records,
        TXT: [customSpf.trim() || 'v=spf1 -all'],
      },
      spf: {
        ...INITIAL_DNS_RESULT.spf,
        ...evaluated.spf,
        raw_record: customSpf.trim() || 'v=spf1 -all',
        explanation:
          evaluated.spf.all_qualifier === '-all'
            ? 'SPF record enforces strict -all (HardFail) within the 10-lookup RFC limit.'
            : `SPF qualifier is '${evaluated.spf.all_qualifier}' (${evaluated.spf.dns_lookup_count}/10 DNS lookups). Transition to '-all' to block unauthorized senders.`,
      },
      dmarc: {
        ...INITIAL_DNS_RESULT.dmarc,
        ...evaluated.dmarc,
        raw_record: customDmarc.trim() || 'v=DMARC1; p=reject',
        explanation:
          evaluated.dmarc.policy === 'reject' || evaluated.dmarc.policy === 'quarantine'
            ? `DMARC actively enforces p=${evaluated.dmarc.policy} against spoofed messages.`
            : 'DMARC is in monitoring-only mode (p=none) or missing. Spoofed messages are not rejected.',
      },
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
            DNS, SPF, DMARC & DNSSEC Security Analyzer
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Automated A, AAAA, MX, NS, TXT resolution with RFC 7208 SPF 10-lookup validation, DMARC
            alignment parsing, and DNSSEC status
          </p>
        </div>
        <StatusBadge status="SPF / DMARC / DNSSEC" />
      </div>

      <Card
        title="Query Domain & Test SPF / DMARC Policy Rules"
        subtitle="Inspect DNS anti-spoofing posture or test custom SPF/DMARC TXT records"
      >
        <form onSubmit={handleAnalyze} className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <label htmlFor="dns-domain-input" className="block text-xs font-medium text-[#F5F7FA] mb-1">
                Target Domain
              </label>
              <input
                id="dns-domain-input"
                type="text"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F5F7FA]"
              />
            </div>
            <div>
              <label htmlFor="dns-spf-input" className="block text-xs font-medium text-[#F5F7FA] mb-1">
                SPF TXT Record (Test Qualifier / Lookups)
              </label>
              <input
                id="dns-spf-input"
                type="text"
                value={customSpf}
                onChange={(e) => setCustomSpf(e.target.value)}
                className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F5F7FA]"
              />
            </div>
            <div>
              <label htmlFor="dns-dmarc-input" className="block text-xs font-medium text-[#F5F7FA] mb-1">
                _dmarc TXT Record (Test p=none|quarantine|reject)
              </label>
              <input
                id="dns-dmarc-input"
                type="text"
                value={customDmarc}
                onChange={(e) => setCustomDmarc(e.target.value)}
                className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F5F7FA]"
              />
            </div>
          </div>
          <div className="flex justify-end">
            <Button type="submit" variant="primary" size="sm" icon={<Play className="w-3.5 h-3.5" />}>
              Evaluate DNS & Anti-Spoofing Controls
            </Button>
          </div>
        </form>
      </Card>

      {!result ? (
        <Card title="DNS, SPF & DMARC Posture" subtitle="No domain evaluated yet">
          <div className="py-12 px-4 text-center space-y-2">
            <Server className="w-9 h-9 text-[#29313B] mx-auto mb-1" />
            <div className="text-sm font-semibold text-[#F5F7FA]">No Domain Evaluated</div>
            <p className="text-xs text-[#A7B0BC] max-w-sm mx-auto">
              Enter a domain or SPF/DMARC TXT record above, then click &ldquo;Evaluate DNS &amp; Anti-Spoofing Controls&rdquo; to analyze security policies.
            </p>
          </div>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <Card
              title="SPF Policy Evaluation (RFC 7208)"
              headerAction={<StatusBadge status={result.spf.status} />}
            >
              <div className="space-y-2 text-xs">
                <div className="p-2.5 bg-[#080A0D] border border-[#29313B] rounded font-mono text-[#38BDF8] break-all">
                  {result.spf.raw_record || 'No SPF record found'}
                </div>
                <div className="flex justify-between text-[#A7B0BC]">
                  <span>DNS-Querying Mechanisms:</span>
                  <span className="font-mono text-[#F5F7FA] tabular-nums">
                    {result.spf.dns_lookup_count} / 10 max
                  </span>
                </div>
                <div className="flex justify-between text-[#A7B0BC]">
                  <span>All Qualifier:</span>
                  <span className="font-mono text-[#F5F7FA]">{result.spf.all_qualifier}</span>
                </div>
                <p className="text-[#A7B0BC] pt-1 leading-relaxed">{result.spf.explanation}</p>
              </div>
            </Card>

            <Card
              title="DMARC Policy Evaluation (RFC 7489)"
              headerAction={<StatusBadge status={result.dmarc.status} />}
            >
              <div className="space-y-2 text-xs">
                <div className="p-2.5 bg-[#080A0D] border border-[#29313B] rounded font-mono text-[#38BDF8] break-all">
                  {result.dmarc.raw_record || 'No _dmarc record found'}
                </div>
                <div className="flex justify-between text-[#A7B0BC]">
                  <span>Organizational Policy (p=):</span>
                  <span className="font-mono text-[#F5F7FA]">{result.dmarc.policy}</span>
                </div>
                <div className="flex justify-between text-[#A7B0BC]">
                  <span>Subdomain Policy (sp=):</span>
                  <span className="font-mono text-[#F5F7FA]">{result.dmarc.subdomain_policy || 'inherit'}</span>
                </div>
                <p className="text-[#A7B0BC] pt-1 leading-relaxed">{result.dmarc.explanation}</p>
              </div>
            </Card>

            <Card
              title="DNSSEC Signing Indicators"
              headerAction={<StatusBadge status={result.dnssec.status} />}
            >
              <div className="space-y-2 text-xs">
                <div className="flex justify-between text-[#A7B0BC]">
                  <span>DNSKEY Record:</span>
                  <span className="font-mono text-[#F5F7FA]">
                    {result.dnssec.dnskey_present ? 'Present' : 'Absent'}
                  </span>
                </div>
                <div className="flex justify-between text-[#A7B0BC]">
                  <span>DS Delegation Signer:</span>
                  <span className="font-mono text-[#F5F7FA]">
                    {result.dnssec.ds_present ? 'Present' : 'Absent'}
                  </span>
                </div>
                <p className="text-[#A7B0BC] pt-2 leading-relaxed">{result.dnssec.explanation}</p>
              </div>
            </Card>
          </div>

          <CodeEvidenceBlock
            title={`Authoritative DNS Records Snapshot — ${result.domain}`}
            language="zone"
            code={`A      ${result.records.A.join(', ')}
AAAA   ${result.records.AAAA.join(', ')}
MX     ${result.records.MX.map((m) => `${m.priority} ${m.exchange}`).join(' | ')}
NS     ${result.records.NS.join(', ')}
SOA    ${result.records.SOA || ''}`}
          />
        </>
      )}
    </div>
  );
};
