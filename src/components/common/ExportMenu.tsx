import React from 'react';
import { Download } from 'lucide-react';
import { BRAND_CONFIG } from '../../config/brand.config';
import { Button } from '../ui/Button';

export const ExportMenu: React.FC<{
  reportCode: string;
  reportTitle: string;
  status: string;
  dataPayload: unknown;
}> = ({ reportCode, reportTitle, status, dataPayload }) => {
  const triggerDownload = (format: 'json' | 'csv' | 'pdf' | 'docx') => {
    const watermark =
      status === 'APPROVED' ? 'APPROVED FINAL REPORT' : 'DRAFT — UNAPPROVED';
    let content = '';
    let mime = 'text/plain;charset=utf-8';
    let ext: string = format;

    if (format === 'json') {
      content = JSON.stringify(
        {
          report_code: reportCode,
          title: reportTitle,
          approval_watermark: watermark,
          attribution: BRAND_CONFIG.BRAND_REPORT_FOOTER,
          exported_at: new Date().toISOString(),
          payload: dataPayload,
        },
        null,
        2
      );
      mime = 'application/json;charset=utf-8';
    } else if (format === 'csv') {
      content = `ReportCode,Title,ApprovalStatus,Attribution,ExportedAt\n"${reportCode}","${reportTitle}","${watermark}","${BRAND_CONFIG.BRAND_REPORT_FOOTER}","${new Date().toISOString()}"\n`;
      mime = 'text/csv;charset=utf-8';
    } else {
      content = `================================================================================\n${BRAND_CONFIG.BRAND_FULL_TITLE} (${BRAND_CONFIG.BRAND_EDITION_NAME})\nTagline: ${BRAND_CONFIG.BRAND_TAGLINE}\nWatermark: [${watermark}]\nReport ID: ${reportCode} — ${reportTitle}\n================================================================================\n\n${JSON.stringify(
        dataPayload,
        null,
        2
      )}\n\n--------------------------------------------------------------------------------\n${BRAND_CONFIG.BRAND_REPORT_FOOTER}\n`;
      ext = format === 'pdf' ? 'pdf.txt' : 'docx.txt';
    }

    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${reportCode.toLowerCase()}-${format}.${ext}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button
        variant="secondary"
        size="sm"
        icon={<Download className="w-3.5 h-3.5" />}
        onClick={() => triggerDownload('pdf')}
      >
        Export PDF
      </Button>
      <Button
        variant="secondary"
        size="sm"
        icon={<Download className="w-3.5 h-3.5" />}
        onClick={() => triggerDownload('docx')}
      >
        Export DOCX
      </Button>
      <Button
        variant="secondary"
        size="sm"
        icon={<Download className="w-3.5 h-3.5" />}
        onClick={() => triggerDownload('json')}
      >
        Export JSON
      </Button>
      <Button
        variant="secondary"
        size="sm"
        icon={<Download className="w-3.5 h-3.5" />}
        onClick={() => triggerDownload('csv')}
      >
        Export CSV
      </Button>
    </div>
  );
};
