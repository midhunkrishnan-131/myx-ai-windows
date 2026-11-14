import React, { useState } from 'react';
import {
  History,
  GitCompare,
  Search,
  Download,
  ExternalLink,
  ShieldCheck,
  AlertTriangle,
  XCircle,
  CheckCircle,
  FileText,
  Calendar,
  Layers,
  Activity,
  ArrowRight,
  TrendingUp,
  TrendingDown,
  Loader2,
  X,
} from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';
import { Button } from '../components/ui/Button';
import { SeverityBadge } from '../components/ui/SeverityBadge';
import { assessmentsService } from '../services/assessments.service';
import { AssessmentRun } from '../types/assessment.types';

export const AssessmentHistoryPage: React.FC = () => {
  const { assessments } = useSystemStatus();

  // Filters & Search
  const [searchTerm, setSearchTerm] = useState('');
  const [moduleFilter, setModuleFilter] = useState<string>('ALL');
  const [scoreFilter, setScoreFilter] = useState<string>('ALL');

  // Interactive Comparison state
  const [baseRunId, setBaseRunId] = useState<string>('');
  const [targetRunId, setTargetRunId] = useState<string>('');
  const [isComparing, setIsComparing] = useState(false);
  const [comparisonData, setComparisonData] = useState<any>(null);
  const [comparisonError, setComparisonError] = useState<string | null>(null);

  // Detail Modal & PDF state
  const [selectedRun, setSelectedRun] = useState<AssessmentRun | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);

  // Filter assessments
  const filtered = assessments.filter((a) => {
    const matchesModule = moduleFilter === 'ALL' || a.module_type === moduleFilter;
    const matchesSearch =
      !searchTerm.trim() ||
      a.target_display.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.profile_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      a.id.toLowerCase().includes(searchTerm.toLowerCase());

    let matchesScore = true;
    if (scoreFilter === 'HIGH') matchesScore = (a.risk_score || 0) >= 80;
    else if (scoreFilter === 'MED') matchesScore = (a.risk_score || 0) >= 50 && (a.risk_score || 0) < 80;
    else if (scoreFilter === 'LOW') matchesScore = (a.risk_score || 0) < 50;

    return matchesModule && matchesSearch && matchesScore;
  });

  // Handle Download PDF
  const handleDownloadPdf = async (runId: string) => {
    setDownloadingId(runId);
    try {
      await assessmentsService.downloadAssessmentPdf(runId, `MYX-Report-${runId}.pdf`);
    } catch (err: any) {
      alert(`PDF download failed: ${err?.message || 'Server error'}`);
    } finally {
      setDownloadingId(null);
    }
  };

  // Handle Run Posture Diff Comparison
  const handleCompare = async () => {
    if (!baseRunId || !targetRunId) {
      setComparisonError('Please select both a Baseline Run and a Comparison Run.');
      return;
    }
    if (baseRunId === targetRunId) {
      setComparisonError('Select two different assessment runs to compare changes.');
      return;
    }

    setIsComparing(true);
    setComparisonError(null);
    try {
      const res = await assessmentsService.compareAssessments(baseRunId, targetRunId);
      setComparisonData(res.data);
    } catch (err: any) {
      setComparisonError(err?.message || 'Comparison failed.');
    } finally {
      setIsComparing(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight flex items-center gap-2">
            <History className="w-6 h-6 text-[#D6AE45]" />
            Unified Assessment History & Posture Diff Ledger
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Audit trail of live Website, Network, Wi-Fi, and Windows security runs with executive PDF exports and posture delta tracking
          </p>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <Card noPadding>
        <div className="p-4 grid grid-cols-1 sm:grid-cols-12 gap-3 items-center">
          <div className="sm:col-span-5 relative">
            <Search className="w-4 h-4 text-[#A7B0BC] absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search by domain, URL, or Run ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-3.5 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
            />
          </div>

          <div className="sm:col-span-4 flex items-center gap-1.5 overflow-x-auto">
            {['ALL', 'WEBSITE', 'NETWORK', 'WINDOWS'].map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => setModuleFilter(m)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium transition-colors shrink-0 ${
                  moduleFilter === m
                    ? 'bg-[#D6AE45] text-[#080A0D]'
                    : 'bg-[#141920] text-[#A7B0BC] hover:text-[#F5F7FA] border border-[#29313B]'
                }`}
              >
                {m}
              </button>
            ))}
          </div>

          <div className="sm:col-span-3">
            <select
              value={scoreFilter}
              onChange={(e) => setScoreFilter(e.target.value)}
              className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
            >
              <option value="ALL">All Scores (0 - 100)</option>
              <option value="HIGH">Score: High (80 - 100)</option>
              <option value="MED">Score: Moderate (50 - 79)</option>
              <option value="LOW">Score: Critical (0 - 49)</option>
            </select>
          </div>
        </div>
      </Card>

      {/* Assessment Runs Table */}
      <Card
        title={`Assessment Records (${filtered.length})`}
        subtitle="Historical security posture audits stored in database with genuine evidence and score breakdowns"
        noPadding
      >
        <div className="overflow-x-auto">
          {filtered.length === 0 ? (
            <div className="py-12 text-center text-xs text-[#A7B0BC]">
              No assessment runs match your active search or filter criteria.
            </div>
          ) : (
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-[#101318] border-b border-[#29313B] text-[11px] font-medium text-[#A7B0BC]">
                  <th className="py-3 px-4">Run ID</th>
                  <th className="py-3 px-4">Module</th>
                  <th className="py-3 px-4">Authorized Target</th>
                  <th className="py-3 px-4 text-center">Score</th>
                  <th className="py-3 px-4 text-right">Pass / Warn / Fail</th>
                  <th className="py-3 px-4">Scan Date</th>
                  <th className="py-3 px-4 text-center">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#29313B] text-xs">
                {filtered.map((run) => {
                  const score = run.risk_score || 0;
                  const scoreColor = score >= 80 ? 'text-[#22C55E]' : score >= 50 ? 'text-[#F59E0B]' : 'text-[#EF4444]';

                  return (
                    <tr key={run.id} className="hover:bg-[#1B222B] transition-colors">
                      <td className="py-3 px-4 font-mono text-[#38BDF8] text-[11px]">{run.id}</td>
                      <td className="py-3 px-4 font-mono font-medium text-[#F5F7FA]">{run.module_type}</td>
                      <td className="py-3 px-4 font-mono text-[#F5F7FA] max-w-[200px] truncate" title={run.target_display}>
                        {run.target_display}
                      </td>
                      <td className="py-3 px-4 text-center">
                        <span className={`font-mono font-bold text-xs ${scoreColor}`}>
                          {score}/100
                        </span>
                      </td>
                      <td className="py-3 px-4 text-right font-mono tabular-nums">
                        <span className="text-[#22C55E]">{run.summary?.passed || 0}P</span> /{' '}
                        <span className="text-[#F59E0B]">{run.summary?.warnings || 0}W</span> /{' '}
                        <span className="text-[#F05252]">{run.summary?.failed || 0}F</span>
                      </td>
                      <td className="py-3 px-4 text-[#A7B0BC] font-mono text-[11px]">
                        {run.completed_at ? new Date(run.completed_at).toLocaleDateString() : 'In Progress'}
                      </td>
                      <td className="py-3 px-4 text-center">
                        <StatusBadge status={run.status} />
                      </td>
                      <td className="py-3 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            type="button"
                            onClick={() => setSelectedRun(run)}
                            className="px-2.5 py-1 bg-[#141920] hover:bg-[#202731] border border-[#29313B] rounded text-[11px] text-[#38BDF8] font-mono transition-colors"
                          >
                            Details
                          </button>
                          <button
                            type="button"
                            disabled={downloadingId === run.id}
                            onClick={() => handleDownloadPdf(run.id)}
                            className="px-2.5 py-1 bg-[#D6AE45]/15 hover:bg-[#D6AE45]/25 border border-[#D6AE45]/40 rounded text-[11px] text-[#D6AE45] font-mono transition-colors flex items-center gap-1 disabled:opacity-50"
                          >
                            {downloadingId === run.id ? (
                              <Loader2 className="w-3 h-3 animate-spin" />
                            ) : (
                              <Download className="w-3 h-3" />
                            )}
                            PDF
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </Card>

      {/* Posture Diff Comparison Tool */}
      <Card
        title="Historical Assessment Posture Diff Comparison"
        subtitle="Compare two historical assessment runs to review security improvements and detect posture regressions"
      >
        <div className="space-y-4">
          <div className="grid grid-cols-1 sm:grid-cols-12 gap-3 items-end">
            <div className="sm:col-span-5">
              <label className="block text-xs font-medium text-[#A7B0BC] mb-1">
                Baseline Assessment (Initial State)
              </label>
              <select
                value={baseRunId}
                onChange={(e) => setBaseRunId(e.target.value)}
                className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
              >
                <option value="">Select baseline assessment run...</option>
                {assessments.map((a) => (
                  <option key={a.id} value={a.id}>
                    [{a.id}] {a.target_display} (Score: {a.risk_score}/100)
                  </option>
                ))}
              </select>
            </div>

            <div className="sm:col-span-5">
              <label className="block text-xs font-medium text-[#A7B0BC] mb-1">
                Comparison Assessment (Current State)
              </label>
              <select
                value={targetRunId}
                onChange={(e) => setTargetRunId(e.target.value)}
                className="w-full px-3 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
              >
                <option value="">Select comparison assessment run...</option>
                {assessments.map((a) => (
                  <option key={a.id} value={a.id}>
                    [{a.id}] {a.target_display} (Score: {a.risk_score}/100)
                  </option>
                ))}
              </select>
            </div>

            <div className="sm:col-span-2">
              <Button
                variant="primary"
                size="sm"
                className="w-full justify-center"
                disabled={isComparing || !baseRunId || !targetRunId}
                onClick={handleCompare}
              >
                {isComparing ? 'Comparing...' : 'Run Diff'}
              </Button>
            </div>
          </div>

          {comparisonError && (
            <div className="p-3 bg-[#EF4444]/10 border border-[#EF4444]/30 rounded-lg text-xs text-[#EF4444]">
              {comparisonError}
            </div>
          )}

          {comparisonData && (
            <div className="space-y-4 pt-2">
              {/* Score Delta Banner */}
              <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="text-xs text-[#A7B0BC]">
                    Posture Score Change:
                  </div>
                  <div className="flex items-center gap-1.5 font-mono text-sm font-bold">
                    <span className="text-[#A7B0BC]">{comparisonData.base_run.risk_score}</span>
                    <ArrowRight className="w-3.5 h-3.5 text-[#737E8C]" />
                    <span className="text-[#F5F7FA]">{comparisonData.target_run.risk_score}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {comparisonData.score_delta > 0 ? (
                    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-bold font-mono bg-[#22C55E]/15 text-[#22C55E] border border-[#22C55E]/30">
                      <TrendingUp className="w-3.5 h-3.5" />
                      +{comparisonData.score_delta} Points Improved
                    </span>
                  ) : comparisonData.score_delta < 0 ? (
                    <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-bold font-mono bg-[#EF4444]/15 text-[#EF4444] border border-[#EF4444]/30">
                      <TrendingDown className="w-3.5 h-3.5" />
                      {comparisonData.score_delta} Points Regressed
                    </span>
                  ) : (
                    <span className="px-2.5 py-0.5 rounded text-xs font-bold font-mono bg-[#A7B0BC]/15 text-[#A7B0BC] border border-[#A7B0BC]/30">
                      Unchanged Posture
                    </span>
                  )}
                </div>
              </div>

              {/* 3 Metric Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg space-y-1">
                  <div className="text-[#A7B0BC] flex items-center gap-1.5">
                    <CheckCircle className="w-3.5 h-3.5 text-[#22C55E]" />
                    <span>Remediated Since Baseline</span>
                  </div>
                  <div className="font-mono font-semibold text-[#22C55E]">
                    +{comparisonData.summary?.remediated_count || 0} Controls Remediated
                  </div>
                  <div className="text-[#737E8C] text-[11px] truncate">
                    {comparisonData.remediated_controls?.map((c: any) => c.title).join(', ') || 'No controls improved'}
                  </div>
                </div>

                <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg space-y-1">
                  <div className="text-[#A7B0BC] flex items-center gap-1.5">
                    <XCircle className="w-3.5 h-3.5 text-[#EF4444]" />
                    <span>Newly Detected Regressions</span>
                  </div>
                  <div className="font-mono font-semibold text-[#EF4444]">
                    {comparisonData.summary?.regressions_count || 0} New Exposure(s)
                  </div>
                  <div className="text-[#737E8C] text-[11px] truncate">
                    {comparisonData.new_regressions?.map((c: any) => c.title).join(', ') || 'No new regressions detected'}
                  </div>
                </div>

                <div className="p-3.5 bg-[#101318] border border-[#29313B] rounded-lg space-y-1">
                  <div className="text-[#A7B0BC] flex items-center gap-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-[#F59E0B]" />
                    <span>Persistent Discrepancies</span>
                  </div>
                  <div className="font-mono font-semibold text-[#F59E0B]">
                    {comparisonData.summary?.persistent_count || 0} Persistent Finding(s)
                  </div>
                  <div className="text-[#737E8C] text-[11px] truncate">
                    {comparisonData.persistent_findings?.map((c: any) => c.title).join(', ') || 'Zero persistent findings'}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </Card>

      {/* Details Modal */}
      {selectedRun && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#080A0D] border border-[#29313B] rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
            <div className="p-4 border-b border-[#29313B] flex items-center justify-between">
              <div>
                <h3 className="text-sm sm:text-base font-bold text-[#F5F7FA] font-mono">
                  {selectedRun.id} — {selectedRun.target_display}
                </h3>
                <p className="text-xs text-[#A7B0BC]">
                  Score: <strong className="text-[#F5F7FA]">{selectedRun.risk_score}/100</strong> · {selectedRun.profile_name}
                </p>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="secondary"
                  size="sm"
                  icon={<Download className="w-3.5 h-3.5 text-[#D6AE45]" />}
                  onClick={() => handleDownloadPdf(selectedRun.id)}
                >
                  Download PDF
                </Button>
                <button
                  type="button"
                  onClick={() => setSelectedRun(null)}
                  className="p-1.5 rounded-lg text-[#A7B0BC] hover:text-[#F5F7FA] hover:bg-[#141920]"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>
            </div>

            <div className="p-4 overflow-y-auto space-y-3">
              {selectedRun.results && selectedRun.results.length > 0 ? (
                selectedRun.results.map((r, i) => (
                  <div key={i} className="p-3 bg-[#101318] border border-[#29313B] rounded-lg space-y-1.5 text-xs">
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-[#F5F7FA]">{r.check_title}</span>
                      <StatusBadge status={r.status} />
                    </div>
                    {r.actual_header_observed && (
                      <div className="font-mono text-[11px] text-[#38BDF8] bg-[#080A0D] p-2 rounded">
                        {r.actual_header_observed}
                      </div>
                    )}
                    {r.technical_explanation && (
                      <div className="text-[#A7B0BC]">{r.technical_explanation}</div>
                    )}
                    {r.remediation_recommendation && (
                      <div className="text-[#D6AE45] font-mono text-[11px]">
                        Remediation: {r.remediation_recommendation}
                      </div>
                    )}
                  </div>
                ))
              ) : (
                <div className="text-center py-8 text-xs text-[#A7B0BC]">
                  No individual check details stored for this assessment run.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
