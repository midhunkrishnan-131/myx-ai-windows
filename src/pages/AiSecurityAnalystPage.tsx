import React, { useState } from 'react';
import { Bot, Send, BookOpen, PlusCircle } from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { GeminiModelTier } from '../types/ai.types';
import { INITIAL_AI_CONVERSATIONS } from '../data/seedPreviewData';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { CodeEvidenceBlock } from '../components/ui/CodeEvidenceBlock';

const QUICK_ANALYST_PROMPTS = [
  'Which findings should I prioritize first?',
  'Explain MYX-FND-2026-0041 and what evidence supports it',
  'How do I remediate RDP without NLA on Windows 11 Pro?',
  'Draft an executive summary for management',
];

export const AiSecurityAnalystPage: React.FC = () => {
  const { aiSessions, ragDocuments, sendAiAnalystPrompt, ingestRagDocument } = useSystemStatus();

  const [modelTier, setModelTier] = useState<GeminiModelTier>('PRIMARY');
  const [promptInput, setPromptInput] = useState('');
  const [newDocTitle, setNewDocTitle] = useState('');
  const [newDocRef, setNewDocRef] = useState('ORG-BASELINE-2026');

  const activeSession = aiSessions[0] || INITIAL_AI_CONVERSATIONS[0];

  const handleSend = (e: React.FormEvent) => {
    e.preventDefault();
    if (!promptInput.trim()) return;
    const targetSessionId = activeSession?.id || 'conv-001';
    sendAiAnalystPrompt(targetSessionId, promptInput.trim(), modelTier);
    setPromptInput('');
  };

  const handleIngestDoc = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDocTitle.trim()) return;
    ingestRagDocument(newDocTitle.trim(), 'ORG_POLICY', newDocRef.trim() || 'ORG-DOC');
    setNewDocTitle('');
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
            AI Security Analyst (Gemini + Tenant-Isolated pgvector RAG)
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Strictly separates Verified Technical Evidence from AI Interpretation · Zero OS Command
            Execution · Prompt-Injection XML Delimiters
          </p>
        </div>
        <StatusBadge status="RAG GROUNDED" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Conversational Analyst Thread */}
        <Card
          title={activeSession?.title || 'AI Security Analyst Session'}
          subtitle={`Attached Context: ${(activeSession?.attached_finding_codes || []).join(', ') || 'General Defensive Security'} · Host: ${(activeSession?.attached_windows_hosts || []).join(', ') || 'WIN11-SECOPS-01'}`}
          className="lg:col-span-2"
          headerAction={
            <select
              aria-label="Select Gemini Model Routing Tier"
              value={modelTier}
              onChange={(e) => setModelTier(e.target.value as GeminiModelTier)}
              className="px-2.5 py-1 bg-[#080A0D] border border-[#29313B] rounded text-xs font-mono text-[#F5F7FA]"
            >
              <option value="FAST">FAST: gemini-3-flash-preview</option>
              <option value="PRIMARY">PRIMARY: gemini-3-flash-preview</option>
              <option value="ADVANCED">ADVANCED: gemini-3-flash-preview (High Reasoning)</option>
            </select>
          }
        >
          <div className="space-y-4">
            {/* Quick Action Prompts */}
            <div className="flex flex-wrap items-center gap-2">
              {QUICK_ANALYST_PROMPTS.map((q) => (
                <button
                  key={q}
                  type="button"
                  onClick={() => {
                    const targetSessionId = activeSession?.id || 'conv-001';
                    sendAiAnalystPrompt(targetSessionId, q, modelTier);
                  }}
                  className="px-2.5 py-1 rounded bg-[#101318] hover:bg-[#1B222B] border border-[#29313B] text-xs text-[#A7B0BC] hover:text-[#F5F7FA] transition-colors"
                >
                  {q}
                </button>
              ))}
            </div>

            {/* Messages */}
            <div className="space-y-4 max-h-[560px] overflow-y-auto pr-1">
              {(activeSession?.messages || []).map((msg) => (
                <div
                  key={msg.id}
                  className={`p-4 rounded-lg border text-xs space-y-3 ${
                    msg.role === 'user'
                      ? 'bg-[#1B222B] border-[#D6AE45]/40'
                      : 'bg-[#101318] border-[#29313B]'
                  }`}
                >
                  <div className="flex items-center justify-between text-[11px] font-mono text-[#737E8C]">
                    <span className="text-[#F5F7FA] font-semibold">
                      {msg.role === 'user'
                        ? 'Security Analyst Query'
                        : `MYX AI Security Copilot (${msg.model_name})`}
                    </span>
                    <span>{msg.created_at}</span>
                  </div>

                  <p className="text-[#F5F7FA] leading-relaxed">{msg.content}</p>

                  {msg.structured_response && (
                    <div className="space-y-3 pt-2 border-t border-[#29313B]">
                      <div className="p-3 bg-[#141920] border border-[#29313B] rounded-lg space-y-1.5">
                        <div className="font-semibold text-[#22C55E]">
                          1. Verified Scanner & Agent Evidence Facts
                        </div>
                        <ul className="list-disc list-inside text-[#A7B0BC] space-y-1">
                          {msg.structured_response.verified_facts.map((vf, idx) => (
                            <li key={idx}>{vf}</li>
                          ))}
                        </ul>
                      </div>

                      <div className="p-3 bg-[#141920] border border-[#29313B] rounded-lg space-y-1">
                        <div className="font-semibold text-[#38BDF8]">
                          2. AI Risk Interpretation
                        </div>
                        <p className="text-[#A7B0BC] leading-relaxed">
                          {msg.structured_response.ai_risk_interpretation}
                        </p>
                      </div>

                      <CodeEvidenceBlock
                        title="3. Non-Executable Defensive Hardening Guidance"
                        code={msg.structured_response.recommended_remediation}
                        language="powershell"
                        isRemediationSnippet
                      />

                      <div className="text-[11px] text-[#A7B0BC] space-y-1">
                        <div>
                          <strong className="text-[#F5F7FA]">Assumptions & Limitations:</strong>{' '}
                          {msg.structured_response.assumptions_and_limitations}
                        </div>
                        <div className="font-mono text-[#737E8C]">
                          Citations:{' '}
                          {msg.structured_response.rag_citations
                            .map((c) => `${c.reference_code} (sim=${c.similarity_score})`)
                            .join(' · ')}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Prompt Input */}
            <form onSubmit={handleSend} className="flex gap-2 pt-2 border-t border-[#29313B]">
              <label htmlFor="ai-analyst-prompt" className="sr-only">
                Ask AI Security Analyst
              </label>
              <input
                id="ai-analyst-prompt"
                type="text"
                value={promptInput}
                onChange={(e) => setPromptInput(e.target.value)}
                placeholder="Query grounded findings, Windows 11 baselines, or OWASP guidance..."
                className="flex-1 px-3.5 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs sm:text-sm text-[#F5F7FA]"
              />
              <Button type="submit" variant="primary" icon={<Send className="w-4 h-4" />}>
                Ask Copilot
              </Button>
            </form>
          </div>
        </Card>

        {/* Tenant-Isolated pgvector RAG Knowledge Base */}
        <Card
          title="PostgreSQL pgvector RAG Corpus"
          subtitle="Enforces WHERE organization_id = :org OR is_global_reference = true"
        >
          <div className="space-y-3">
            {ragDocuments.map((doc) => (
              <div
                key={doc.id}
                className="p-3 bg-[#101318] border border-[#29313B] rounded-lg space-y-1 text-xs"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-[#F5F7FA] truncate">{doc.title}</span>
                  <span className="font-mono text-[10px] text-[#38BDF8] shrink-0">
                    {doc.chunk_count} chunks
                  </span>
                </div>
                <div className="text-[11px] font-mono text-[#737E8C]">
                  {doc.source_reference} ·{' '}
                  {doc.is_global_reference ? 'Global Reference' : 'Tenant Private'}
                </div>
              </div>
            ))}

            <form
              onSubmit={handleIngestDoc}
              className="pt-3 border-t border-[#29313B] space-y-2.5 text-xs"
            >
              <div className="font-semibold text-[#F5F7FA] flex items-center gap-1.5">
                <BookOpen className="w-3.5 h-3.5 text-[#38BDF8]" />
                <span>Ingest Tenant Security Policy Document</span>
              </div>
              <input
                type="text"
                placeholder="Document Title (e.g. Windows 11 Hardening Standard)"
                value={newDocTitle}
                onChange={(e) => setNewDocTitle(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#080A0D] border border-[#29313B] rounded text-xs text-[#F5F7FA]"
              />
              <input
                type="text"
                placeholder="Reference ID (e.g. ORG-WIN11-STD)"
                value={newDocRef}
                onChange={(e) => setNewDocRef(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#080A0D] border border-[#29313B] rounded text-xs font-mono text-[#F5F7FA]"
              />
              <Button
                type="submit"
                variant="secondary"
                size="sm"
                icon={<PlusCircle className="w-3.5 h-3.5" />}
                className="w-full"
              >
                Sanitize, Chunk & Index in pgvector
              </Button>
            </form>
          </div>
        </Card>
      </div>
    </div>
  );
};
