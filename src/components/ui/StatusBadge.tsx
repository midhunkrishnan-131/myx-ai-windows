import React from 'react';

export const StatusBadge: React.FC<{ status: string }> = ({ status }) => {
  const normalized = status.toUpperCase();

  let colorClass = 'bg-[#38BDF8]/15 text-[#38BDF8] border-[#38BDF8]/40';

  if (
    [
      'CONNECTED',
      'VERIFIED',
      'PASS',
      'PASSED',
      'FIXED',
      'APPROVED',
      'ACTIVE',
      'COMPLETED',
      'NO KNOWN THREAT DETECTED',
      'REVIEWER_APPROVED',
      'PARSED',
    ].includes(normalized)
  ) {
    colorClass = 'bg-[#22C55E]/15 text-[#22C55E] border-[#22C55E]/40';
  } else if (
    [
      'WARNING',
      'IN PROGRESS',
      'IN_REVIEW',
      'PENDING',
      'UNAVAILABLE',
      'SUSPICIOUS',
      'REQUIRES_ELEVATION',
      'UNSUPPORTED',
      'AI_DRAFT_PENDING_REVIEW',
      'ACCEPTED RISK',
      'HUMAN_EDITED',
    ].includes(normalized)
  ) {
    colorClass = 'bg-[#F59E0B]/15 text-[#F59E0B] border-[#F59E0B]/40';
  } else if (
    [
      'FAIL',
      'FAILED',
      'OPEN',
      'REOPENED',
      'MISCONFIGURED',
      'REVOKED',
      'EXPIRED',
      'KNOWN MALICIOUS MATCH',
    ].includes(normalized)
  ) {
    colorClass = 'bg-[#F05252]/15 text-[#F05252] border-[#F05252]/40';
  } else if (['DISCONNECTED', 'OFFLINE', 'FALSE POSITIVE', 'ARCHIVED', 'CLOSED'].includes(normalized)) {
    colorClass = 'bg-[#737E8C]/15 text-[#A7B0BC] border-[#737E8C]/40';
  }

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium border whitespace-nowrap shrink-0 ${colorClass}`}
    >
      {status}
    </span>
  );
};
