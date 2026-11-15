import React from 'react';
import { Link } from 'react-router-dom';
import { FileCheck2, FilePenLine } from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { INITIAL_REPORTS } from '../data/seedPreviewData';
import { BRAND_CONFIG } from '../config/brand.config';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';
import { ExportMenu } from '../components/common/ExportMenu';

export const ReportsRepositoryPage: React.FC = () => {
  const { reports } = useSystemStatus();
  // Filter out static demo reports so real live assessment reports take priority
  const realReports = reports.filter((r) => !r.id.startsWith('demo-') && !r.id.startsWith('rpt-2026-'));

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-[#29313B]">
        <div>
          <h1 className="text-xl sm:text-2xl font-bold text-[#F5F7FA] tracking-tight">
            Security Reports Repository & Deliverable Archive
          </h1>
          <p className="text-xs sm:text-sm text-[#A7B0BC] mt-1">
            Draft, In-Review, and Approved executive/technical reports with version snapshots and
            PDF/DOCX/JSON/CSV artifact export
          </p>
        </div>
        <Link
          to="/reports/studio"
          className="inline-flex items-center gap-2 px-3.5 py-2 bg-[#D6AE45] hover:bg-[#E7C66A] rounded-lg text-xs font-medium text-[#F5F7FA] transition-colors whitespace-nowrap shrink-0"
        >
          <FilePenLine className="w-4 h-4" />
          <span>Open AI Report Studio</span>
        </Link>
      </div>

      {realReports.length === 0 ? (
        <div className="py-16 px-6 text-center bg-[#101318] border border-[#29313B] rounded-xl space-y-4">
          <div className="w-12 h-12 rounded-full bg-[#D6AE45]/15 text-[#D6AE45] flex items-center justify-center mx-auto">
            <FileCheck2 className="w-6 h-6" />
          </div>
          <div className="space-y-1">
            <h3 className="text-base font-semibold text-[#F5F7FA]">No Live Deliverable Reports Yet</h3>
            <p className="text-xs text-[#A7B0BC] max-w-md mx-auto leading-relaxed">
              Scan any live website URL or domain in the Website Assessment module. As soon as the assessment completes, a real, comprehensive security assessment report will be automatically generated and archived here with PDF/DOCX export.
            </p>
          </div>
          <Link
            to="/assessments/website"
            className="inline-flex items-center gap-2 px-4 py-2 bg-[#D6AE45] hover:bg-[#E7C66A] rounded-lg text-xs font-semibold text-[#080A0D] transition-colors"
          >
            Go to Website Assessment & Scan Link
          </Link>
        </div>
      ) : (
        <div className="space-y-4">
          {realReports.map((rpt) => (
          <Card
            key={rpt.id}
            title={`${rpt.report_code} — ${rpt.title}`}
            subtitle={`Project: ${rpt.project_name} · Window: ${rpt.assessment_date_window} · Version: ${rpt.current_version}`}
            headerAction={<StatusBadge status={rpt.status} />}
            footer={
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <span>{BRAND_CONFIG.BRAND_REPORT_FOOTER}</span>
                <span className="font-mono">
                  {rpt.approved_by_email
                    ? `Approved by ${rpt.approved_by_email} at ${rpt.approved_at}`
                    : `Assigned Reviewer: ${rpt.assigned_reviewer_email}`}
                </span>
              </div>
            }
          >
            <div className="space-y-4 text-xs">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
                  <div className="text-[#A7B0BC]">Authorized Scope Targets</div>
                  <div className="font-mono text-[#F5F7FA] mt-1">
                    {rpt.scope_targets.join(', ')}
                  </div>
                </div>
                <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
                  <div className="text-[#A7B0BC]">Included Findings</div>
                  <div className="font-mono text-[#38BDF8] mt-1">
                    {rpt.included_finding_codes.join(', ')}
                  </div>
                </div>
                <div className="p-3 bg-[#101318] border border-[#29313B] rounded-lg">
                  <div className="text-[#A7B0BC]">Version History</div>
                  <div className="font-mono text-[#F5F7FA] mt-1">
                    {rpt.versions.map((v) => `${v.version_number} (${v.status})`).join(' → ')}
                  </div>
                </div>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t border-[#29313B]">
                <div className="text-[#A7B0BC]">
                  Export Watermark:{' '}
                  <strong className="font-mono text-[#F5F7FA]">
                    {rpt.status === 'APPROVED' ? 'APPROVED FINAL REPORT' : 'DRAFT — UNAPPROVED'}
                  </strong>
                </div>
                <ExportMenu
                  reportCode={rpt.report_code}
                  reportTitle={rpt.title}
                  status={rpt.status}
                  dataPayload={rpt}
                />
              </div>
            </div>
          </Card>
        ))}
        </div>
      )}
    </div>
  );
};
