import React, { useState } from 'react';
import { Lock, Play } from 'lucide-react';
import { INITIAL_SSL_TLS_RESULT } from '../data/seedPreviewData';
import { SslTlsAnalysisResult } from '../types/assessment.types';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { CodeEvidenceBlock } from '../components/ui/CodeEvidenceBlock';

export const SslTlsAnalyzerPage: React.FC = () => {
  const [hostname, setHostname] = useState('portal.myx-defense-demo.org');
  const [port, setPort] = useState(443);
  const [result, setResult] = useState<SslTlsAnalysisResult>(INITIAL_SSL_TLS_RESULT);

  const handleInspect = (e: React.FormEvent) => {
    e.preventDefault();
    if (!hostname.trim()) return;
    setResult({
      ...INITIAL_SSL_TLS_RESULT,
      target_hostname: hostname.trim(),
      port,
      analyzed_at: new Date().toISOString(),
    });
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
            SSL/TLS Certificate & Protocol Analyzer
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            X.509 certificate chain verification, SAN matching, expiration countdown, TLS 1.0–1.3
            protocol matrix, and cipher inspection
          </p>
        </div>
        <StatusBadge status="DEMO / SAMPLE PREVIEW" />
      </div>

      <Card
        title="Inspect X.509 Certificate Chain & TLS Handshake"
        subtitle="Connects to authorized hostnames and evaluates RFC 8996 TLS deprecation compliance"
      >
        <form onSubmit={handleInspect} className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1">
            <label htmlFor="tls-hostname" className="sr-only">
              Target Hostname
            </label>
            <input
              id="tls-hostname"
              type="text"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
              placeholder="portal.myx-defense-demo.org"
              className="w-full px-3.5 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs sm:text-sm font-mono text-[#F5F7FA]"
            />
          </div>
          <div className="w-full sm:w-28">
            <label htmlFor="tls-port" className="sr-only">
              TLS Port
            </label>
            <input
              id="tls-port"
              type="number"
              value={port}
              onChange={(e) => setPort(Number(e.target.value) || 443)}
              className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs sm:text-sm font-mono text-[#F5F7FA]"
            />
          </div>
          <Button type="submit" variant="primary" icon={<Play className="w-4 h-4" />}>
            Inspect TLS Endpoint
          </Button>
        </form>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <Card
          title={`X.509 Certificate Metadata — ${result.target_hostname}:${result.port}`}
          subtitle="Validates Subject CN, SANs, RSA key length (>= 2048 bits), and signature algorithm"
          className="lg:col-span-2"
        >
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
              <div className="text-[#A7B0BC]">Subject Common Name (CN)</div>
              <div className="font-mono font-semibold text-[#F5F7FA] mt-1">
                {result.certificate.subject_cn}
              </div>
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
              <div className="text-[#A7B0BC]">Subject Alternative Names (SANs)</div>
              <div className="font-mono text-[#38BDF8] mt-1">
                {result.certificate.sans.join(', ')}
              </div>
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
              <div className="text-[#A7B0BC]">Issuer Organization & CA</div>
              <div className="font-semibold text-[#F5F7FA] mt-1">
                {result.certificate.issuer_org} — {result.certificate.issuer_cn}
              </div>
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
              <div className="text-[#A7B0BC]">Expiration Countdown</div>
              <div className="font-mono font-semibold text-[#F59E0B] mt-1 tabular-nums">
                {result.certificate.days_until_expiry} days remaining (Warning &lt; 30d)
              </div>
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
              <div className="text-[#A7B0BC]">Public Key & Signature</div>
              <div className="font-mono text-[#F5F7FA] mt-1">
                {result.certificate.public_key_algorithm} {result.certificate.public_key_bits}-bit ·{' '}
                {result.certificate.signature_algorithm}
              </div>
            </div>
            <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
              <div className="text-[#A7B0BC]">Negotiated Cipher Suite</div>
              <div className="font-mono text-[#22C55E] mt-1">
                {result.negotiated_cipher.name} ({result.negotiated_cipher.tls_version})
              </div>
            </div>
          </div>
        </Card>

        <Card
          title="Protocol Version Matrix"
          subtitle="SSLv3 / TLS 1.0 / TLS 1.1 / TLS 1.2 / TLS 1.3"
        >
          <div className="space-y-2.5">
            {result.protocols.map((p) => (
              <div
                key={p.version}
                className="p-3 bg-[#101318] border border-[#29313B] rounded-lg space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-xs font-semibold text-[#F5F7FA]">
                    {p.version}
                  </span>
                  <StatusBadge status={p.status} />
                </div>
                <p className="text-[11px] text-[#A7B0BC]">{p.notes}</p>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <CodeEvidenceBlock
        title="Recommended nginx TLS 1.2 / 1.3 Hardening Configuration"
        language="nginx"
        isRemediationSnippet
        code={`ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';`}
      />
    </div>
  );
};
