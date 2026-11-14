import React from 'react';
import { Link } from 'react-router-dom';
import { FileCheck2, FilePenLine } from 'lucide-react';
import { useSystemStatus } from '../context/SystemStatusContext';
import { BRAND_CONFIG } from '../config/brand.config';
import { Card } from '../components/ui/Card';
import { StatusBadge } from '../components/ui/StatusBadge';
import { ExportMenu } from '../components/common/ExportMenu';

export const ReportsRepositoryPage: React.FC = () => {
  const { reports } = useSystemStatus();

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

      <div className="space-y-4">
        {reports.map((rpt) => (
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
    </div>
  );
};
