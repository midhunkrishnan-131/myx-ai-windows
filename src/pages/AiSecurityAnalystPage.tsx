import React, { useState, useRef, useEffect } from 'react';
import {
  Bot,
  Send,
  BookOpen,
  PlusCircle,
  RotateCcw,
  Download,
  Copy,
  Check,
  ThumbsUp,
  ThumbsDown,
  Sparkles,
  ShieldCheck,
  Terminal,
  Layers,
  Globe,
  Loader2,
  Trash2,
} from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { GeminiModelTier } from '../types/ai.types';
import { INITIAL_AI_CONVERSATIONS } from '../data/seedPreviewData';
import { Card } from '../components/ui/Card';
import { Button } from '../components/ui/Button';
import { StatusBadge } from '../components/ui/StatusBadge';
import { CodeEvidenceBlock } from '../components/ui/CodeEvidenceBlock';

export const AiSecurityAnalystPage: React.FC = () => {
  const { aiSessions, ragDocuments, sendAiAnalystPrompt, clearAiSession, ingestRagDocument } =
    useSystemStatus();

  const [modelTier, setModelTier] = useState<GeminiModelTier>('PRIMARY');
  const [promptInput, setPromptInput] = useState('');
  const [newDocTitle, setNewDocTitle] = useState('');
  const [newDocRef, setNewDocRef] = useState('ORG-BASELINE-2026');
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [reactions, setReactions] = useState<Record<string, 'up' | 'down'>>({});
  const [isThinking, setIsThinking] = useState(false);
  const [ingestSuccess, setIngestSuccess] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const activeSession = aiSessions[0] || INITIAL_AI_CONVERSATIONS[0];

  const hasAttachedFindings = (activeSession?.attached_finding_codes || []).length > 0;
  const hasAttachedHost = (activeSession?.attached_windows_hosts || []).length > 0;

  const quickPrompts = hasAttachedFindings
    ? [
        `Prioritize findings: ${activeSession.attached_finding_codes.slice(0, 3).join(', ')}`,
        `How do I remediate ${activeSession.attached_finding_codes[0]} safely?`,
        'Draft an executive risk summary for management',
        `Generate defensive verification checklist for ${activeSession.attached_windows_hosts?.[0] || 'target'}`,
      ]
    : [
        'How do I configure Strict-Transport-Security (HSTS)?',
        'What is a hardened Content-Security-Policy (CSP)?',
        'Explain OWASP Top 10 web vulnerabilities and defenses',
        'Best practices for Windows 11 endpoint hardening',
        'What cipher suites should I allow for TLS 1.3?',
      ];

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [activeSession?.messages?.length, isThinking]);

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault();
    const text = promptInput.trim();
    if (!text || isThinking) return;

    const targetSessionId = activeSession?.id || 'conv-general-01';
    setPromptInput('');
    setIsThinking(true);

    try {
      sendAiAnalystPrompt(targetSessionId, text, modelTier);
      // Brief animated thinking pause to let Gemini synthesis complete
      await new Promise((resolve) => setTimeout(resolve, 800));
    } finally {
      setIsThinking(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend(e);
    }
  };

  const handleQuickPromptClick = (text: string) => {
    const targetSessionId = activeSession?.id || 'conv-general-01';
    setIsThinking(true);
    sendAiAnalystPrompt(targetSessionId, text, modelTier);
    setTimeout(() => setIsThinking(false), 800);
  };

  const handleCopy = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleReaction = (id: string, type: 'up' | 'down') => {
    setReactions((prev) => ({
      ...prev,
      [id]: prev[id] === type ? (undefined as any) : type,
    }));
  };

  const handleClearChat = () => {
    if (activeSession?.id && window.confirm('Clear all conversation messages in this session?')) {
      clearAiSession(activeSession.id);
    }
  };

  const handleExportChat = () => {
    if (!activeSession) return;
    const lines = [
      `# ${activeSession.title}`,
      `Exported: ${new Date().toISOString()}`,
      `Attached Context: ${activeSession.attached_finding_codes?.join(', ') || 'General Defensive Security'}`,
      `Attached Scope: ${activeSession.attached_windows_hosts?.join(', ') || 'N/A'}`,
      '',
      '---',
      '',
    ];
    (activeSession.messages || []).forEach((m) => {
      lines.push(
        `### ${m.role === 'user' ? 'Security Analyst' : `MYX AI Copilot (${m.model_name})`} [${m.created_at}]`
      );
      lines.push('');
      lines.push(m.content);
      lines.push('');
      if (m.structured_response?.recommended_remediation) {
        lines.push('#### Hardening Remediation Snippet:');
        lines.push('```powershell');
        lines.push(m.structured_response.recommended_remediation);
        lines.push('```');
        lines.push('');
      }
    });

    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `myx-ai-analyst-transcript-${Date.now()}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleIngestDoc = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDocTitle.trim()) return;
    ingestRagDocument(newDocTitle.trim(), 'ORG_POLICY', newDocRef.trim() || 'ORG-DOC');
    setIngestSuccess(`Successfully indexed "${newDocTitle.trim()}" in pgvector RAG memory.`);
    setNewDocTitle('');
    setTimeout(() => setIngestSuccess(null), 3500);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <div className="flex items-center gap-2.5">
            <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
              AI Security Analyst Copilot
            </h1>
            <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#D6AE45]/15 text-[#D6AE45] border border-[#D6AE45]/30">
              Gemini + pgvector RAG
            </span>
          </div>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Separates Verified Technical Evidence from AI Interpretation · Zero OS Command Execution ·
            Prompt-Injection XML Delimiters
          </p>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge status="RAG GROUNDED" />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Conversational Analyst Thread */}
        <Card
          title={activeSession?.title || 'AI Security Analyst Session'}
          subtitle={
            hasAttachedFindings || hasAttachedHost
              ? `Attached Scope: ${activeSession.attached_windows_hosts.join(', ') || 'N/A'} · Findings: ${activeSession.attached_finding_codes.join(', ')}`
              : 'Defensive Mode: General Cybersecurity Guidance · pgvector RAG Active'
          }
          className="lg:col-span-2"
          headerAction={
            <div className="flex items-center gap-2">
              <select
                aria-label="Select Gemini Model Routing Tier"
                value={modelTier}
                onChange={(e) => setModelTier(e.target.value as GeminiModelTier)}
                className="px-2.5 py-1 bg-[#080A0D] border border-[#29313B] rounded text-xs font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
              >
                <option value="FAST">FAST: gemini-3-flash-preview</option>
                <option value="PRIMARY">PRIMARY: gemini-3-flash-preview</option>
                <option value="ADVANCED">ADVANCED: High Reasoning</option>
              </select>

              <button
                type="button"
                onClick={handleExportChat}
                title="Export Transcript (Markdown)"
                className="p-1.5 rounded bg-[#101318] hover:bg-[#1B222B] border border-[#29313B] text-[#A7B0BC] hover:text-[#F5F7FA] transition-colors"
              >
                <Download className="w-3.5 h-3.5" />
              </button>

              <button
                type="button"
                onClick={handleClearChat}
                title="Clear Session Chat"
                className="p-1.5 rounded bg-[#101318] hover:bg-[#1B222B] border border-[#29313B] text-[#A7B0BC] hover:text-[#EF4444] transition-colors"
              >
                <Trash2 className="w-3.5 h-3.5" />
              </button>
            </div>
          }
        >
          <div className="space-y-4">
            {/* Quick Action Prompts */}
            <div className="space-y-1.5">
              <div className="text-[11px] font-mono text-[#737E8C] flex items-center gap-1.5">
                <Sparkles className="w-3 h-3 text-[#D6AE45]" />
                <span>Suggested Defensive Prompts:</span>
              </div>
              <div className="flex flex-wrap items-center gap-2">
                {quickPrompts.map((q) => (
                  <button
                    key={q}
                    type="button"
                    onClick={() => handleQuickPromptClick(q)}
                    className="px-2.5 py-1 rounded-md bg-[#101318] hover:bg-[#1B222B] border border-[#29313B] hover:border-[#D6AE45]/40 text-xs text-[#A7B0BC] hover:text-[#F5F7FA] transition-colors text-left"
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>

            {/* Messages Thread */}
            <div className="space-y-4 max-h-[560px] overflow-y-auto pr-1">
              {(activeSession?.messages || []).length === 0 ? (
                <div className="py-12 px-4 text-center text-xs text-[#A7B0BC] space-y-2 bg-[#101318]/50 border border-[#29313B] rounded-lg">
                  <Bot className="w-8 h-8 text-[#D6AE45] mx-auto opacity-70" />
                  <div className="font-semibold text-[#F5F7FA]">Ready to assist</div>
                  <p className="max-w-md mx-auto">
                    Ask any question about defensive security, posture remediation, OWASP standards,
                    or click a suggested prompt above.
                  </p>
                </div>
              ) : (
                (activeSession?.messages || []).map((msg) => {
                  const isUser = msg.role === 'user';
                  const isCopied = copiedId === msg.id;
                  const currentReaction = reactions[msg.id];

                  return (
                    <div
                      key={msg.id}
                      className={`p-4 rounded-lg border text-xs space-y-3 transition-colors ${
                        isUser
                          ? 'bg-[#18202A] border-[#D6AE45]/40 ml-4 sm:ml-8'
                          : 'bg-[#101318] border-[#29313B] mr-4 sm:mr-8'
                      }`}
                    >
                      {/* Message Header */}
                      <div className="flex items-center justify-between text-[11px] font-mono text-[#737E8C]">
                        <div className="flex items-center gap-2">
                          <div
                            className={`w-5 h-5 rounded flex items-center justify-center text-[10px] font-bold ${
                              isUser
                                ? 'bg-[#D6AE45] text-[#080A0D]'
                                : 'bg-[#38BDF8]/20 text-[#38BDF8]'
                            }`}
                          >
                            {isUser ? 'YOU' : 'AI'}
                          </div>
                          <span className="text-[#F5F7FA] font-semibold">
                            {isUser
                              ? 'Security Analyst Query'
                              : `MYX AI Copilot (${msg.model_name || 'gemini-3-flash-preview'})`}
                          </span>
                        </div>

                        <div className="flex items-center gap-1.5">
                          <span>{msg.created_at ? new Date(msg.created_at).toLocaleTimeString() : ''}</span>
                          <button
                            type="button"
                            onClick={() => handleCopy(msg.id, msg.content)}
                            title="Copy message"
                            className="p-1 hover:text-[#F5F7FA] transition-colors"
                          >
                            {isCopied ? (
                              <Check className="w-3.5 h-3.5 text-[#22C55E]" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        </div>
                      </div>

                      {/* Message Body */}
                      <p className="text-[#F5F7FA] leading-relaxed whitespace-pre-wrap">{msg.content}</p>

                      {/* Structured Response Breakdown */}
                      {msg.structured_response && (
                        <div className="space-y-3 pt-2 border-t border-[#29313B]">
                          {msg.structured_response.verified_facts && msg.structured_response.verified_facts.length > 0 && (
                            <div className="p-3 bg-[#141920] border border-[#29313B] rounded-lg space-y-1.5">
                              <div className="font-semibold text-[#22C55E] flex items-center gap-1.5">
                                <ShieldCheck className="w-3.5 h-3.5 text-[#22C55E]" />
                                <span>1. Verified Scanner & Evidence Facts</span>
                              </div>
                              <ul className="list-disc list-inside text-[#A7B0BC] space-y-1">
                                {msg.structured_response.verified_facts.map((vf, idx) => (
                                  <li key={idx}>{vf}</li>
                                ))}
                              </ul>
                            </div>
                          )}

                          {msg.structured_response.ai_risk_interpretation && (
                            <div className="p-3 bg-[#141920] border border-[#29313B] rounded-lg space-y-1">
                              <div className="font-semibold text-[#38BDF8] flex items-center gap-1.5">
                                <Sparkles className="w-3.5 h-3.5 text-[#38BDF8]" />
                                <span>2. AI Risk Interpretation</span>
                              </div>
                              <p className="text-[#A7B0BC] leading-relaxed">
                                {msg.structured_response.ai_risk_interpretation}
                              </p>
                            </div>
                          )}

                          {msg.structured_response.recommended_remediation && (
                            <CodeEvidenceBlock
                              title="3. Non-Executable Defensive Hardening Guidance"
                              code={msg.structured_response.recommended_remediation}
                              language="powershell"
                              isRemediationSnippet
                            />
                          )}

                          {msg.structured_response.assumptions_and_limitations && (
                            <div className="text-[11px] text-[#A7B0BC] space-y-1">
                              <div>
                                <strong className="text-[#F5F7FA]">Assumptions & Limitations:</strong>{' '}
                                {msg.structured_response.assumptions_and_limitations}
                              </div>
                            </div>
                          )}
                        </div>
                      )}

                      {/* Assistant Message Reactions */}
                      {!isUser && (
                        <div className="flex items-center justify-between pt-1 text-[11px] text-[#737E8C]">
                          <div className="flex items-center gap-2">
                            <span>Was this response helpful?</span>
                            <button
                              type="button"
                              onClick={() => handleReaction(msg.id, 'up')}
                              className={`p-1 rounded hover:text-[#F5F7FA] transition-colors ${
                                currentReaction === 'up' ? 'text-[#22C55E]' : ''
                              }`}
                              title="Helpful"
                            >
                              <ThumbsUp className="w-3.5 h-3.5" />
                            </button>
                            <button
                              type="button"
                              onClick={() => handleReaction(msg.id, 'down')}
                              className={`p-1 rounded hover:text-[#F5F7FA] transition-colors ${
                                currentReaction === 'down' ? 'text-[#EF4444]' : ''
                              }`}
                              title="Not helpful"
                            >
                              <ThumbsDown className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })
              )}

              {/* Thinking Indicator */}
              {isThinking && (
                <div className="p-4 rounded-lg border border-[#38BDF8]/30 bg-[#101318] mr-4 sm:mr-8 text-xs space-y-2 animate-pulse">
                  <div className="flex items-center gap-2 text-[#38BDF8] font-mono text-[11px]">
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>MYX AI Copilot is synthesizing response...</span>
                  </div>
                  <p className="text-[#A7B0BC] text-xs">
                    Consulting pgvector RAG memory, verifying evidence facts, and enforcing anti-hallucination guardrails.
                  </p>
                </div>
              )}

              <div ref={messagesEndRef} />
            </div>

            {/* Prompt Input Area */}
            <form onSubmit={handleSend} className="space-y-2 pt-2 border-t border-[#29313B]">
              <div className="relative">
                <textarea
                  rows={2}
                  value={promptInput}
                  onChange={(e) => setPromptInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  placeholder="Ask a security question, analyze findings, or request remediation guidance... (Press Enter to send, Shift+Enter for new line)"
                  className="w-full px-3.5 py-2.5 bg-[#080A0D] border border-[#29313B] focus:border-[#D6AE45] rounded-lg text-xs sm:text-sm text-[#F5F7FA] resize-none outline-none transition-colors"
                />
              </div>

              <div className="flex items-center justify-between text-[11px] text-[#737E8C]">
                <div className="flex items-center gap-2">
                  <span className="flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-[#22C55E]"></span>
                    <span>RAG Grounding: Active</span>
                  </span>
                  <span>·</span>
                  <span>Zero OS Execution</span>
                </div>

                <Button
                  type="submit"
                  variant="primary"
                  size="sm"
                  disabled={!promptInput.trim() || isThinking}
                  icon={isThinking ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                >
                  Ask Copilot
                </Button>
              </div>
            </form>
          </div>
        </Card>

        {/* Tenant-Isolated pgvector RAG Knowledge Base */}
        <Card
          title="PostgreSQL pgvector RAG Corpus"
          subtitle="Enforces WHERE organization_id = :org OR is_global_reference = true"
        >
          <div className="space-y-3">
            {ingestSuccess && (
              <div className="p-2.5 bg-[#22C55E]/10 border border-[#22C55E]/30 rounded-lg text-xs text-[#22C55E] flex items-center gap-2">
                <Check className="w-3.5 h-3.5 shrink-0" />
                <span>{ingestSuccess}</span>
              </div>
            )}

            <div className="space-y-2">
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
            </div>

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
                placeholder="Document Title (e.g. Windows Hardening Standard)"
                value={newDocTitle}
                onChange={(e) => setNewDocTitle(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#080A0D] border border-[#29313B] rounded text-xs text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
              />
              <input
                type="text"
                placeholder="Reference ID (e.g. ORG-SEC-POL-2026)"
                value={newDocRef}
                onChange={(e) => setNewDocRef(e.target.value)}
                className="w-full px-3 py-1.5 bg-[#080A0D] border border-[#29313B] rounded text-xs font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
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
