import React from 'react';
import { SeverityLevel } from '../../types/assessment.types';

export const SeverityBadge: React.FC<{ severity: SeverityLevel }> = ({ severity }) => {
  const styles: Record<SeverityLevel, string> = {
    Critical: 'bg-[#F05252]/15 text-[#F05252] border-[#F05252]/40',
    High: 'bg-[#F59E0B]/15 text-[#F59E0B] border-[#F59E0B]/40',
    Medium: 'bg-[#F59E0B]/15 text-[#F59E0B] border-[#F59E0B]/30',
    Low: 'bg-[#22C55E]/15 text-[#22C55E] border-[#22C55E]/40',
    Informational: 'bg-[#38BDF8]/15 text-[#38BDF8] border-[#38BDF8]/40',
  };

  return (
    <span
      className={`inline-flex items-center px-2.5 py-0.5 rounded text-xs font-medium border whitespace-nowrap shrink-0 ${
        styles[severity] || styles.Informational
      }`}
    >
      {severity}
    </span>
  );
};
