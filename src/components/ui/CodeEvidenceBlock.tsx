import React, { useState } from 'react';
import { Check, Copy, ShieldAlert, Lock } from 'lucide-react';

export interface CodeEvidenceBlockProps {
  title?: string;
  code?: string | null;
  language?: string;
  isRemediationSnippet?: boolean;
  secretsRedacted?: boolean;
}

export const CodeEvidenceBlock: React.FC<CodeEvidenceBlockProps> = ({
  title = 'Technical Evidence / Configuration Output',
  code = '',
  language = 'text',
  isRemediationSnippet = false,
  secretsRedacted = true,
}) => {
  const [copied, setCopied] = useState(false);

  const safeCode = typeof code === 'string' ? code : (code != null ? String(code) : '');

  const handleCopy = async () => {
    try {
      if (navigator.clipboard) {
        await navigator.clipboard.writeText(safeCode);
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
      }
    } catch {
      setCopied(false);
    }
  };

  const lines = safeCode ? safeCode.split('\n') : ['(No evidence recorded)'];

  return (
    <div className="bg-[#080A0D] border border-[#29313B] rounded-lg overflow-hidden">
      {isRemediationSnippet && (
        <div className="px-3.5 py-2 bg-[#F59E0B]/10 border-b border-[#F59E0B]/30 flex items-center gap-2 text-xs text-[#F59E0B]">
          <ShieldAlert className="w-4 h-4 shrink-0" aria-hidden="true" />
          <span>
            Non-Executable Remediation Guidance: Review and test all configuration changes in a
            non-production environment before applying.
          </span>
        </div>
      )}
      <div className="px-3.5 py-2 bg-[#101318] border-b border-[#29313B] flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-3 text-xs text-[#A7B0BC]">
          <span className="font-medium text-[#F5F7FA]">{title}</span>
          <span aria-hidden="true">·</span>
          <span className="font-mono text-[#737E8C]">{language}</span>
          {secretsRedacted && (
            <>
              <span aria-hidden="true">·</span>
              <span className="inline-flex items-center gap-1 text-[#22C55E]">
                <Lock className="w-3 h-3" aria-hidden="true" />
                Secrets Redacted
              </span>
            </>
          )}
        </div>
        <button
          type="button"
          onClick={handleCopy}
          aria-label={`Copy ${title}`}
          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs text-[#A7B0BC] hover:text-[#F5F7FA] hover:bg-[#1B222B] transition-colors whitespace-nowrap shrink-0"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-[#22C55E]" />
              <span className="text-[#22C55E]">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span>Copy</span>
            </>
          )}
        </button>
      </div>
      <div className="p-3.5 overflow-x-auto">
        <pre className="font-mono text-xs leading-relaxed text-[#F5F7FA] tabular-nums">
          {lines.map((line, idx) => (
            <div key={idx} className="table-row">
              <span className="table-cell pr-4 select-none text-right text-[#737E8C] w-8">
                {idx + 1}
              </span>
              <span className="table-cell whitespace-pre">{line}</span>
            </div>
          ))}
        </pre>
      </div>
    </div>
  );
};
