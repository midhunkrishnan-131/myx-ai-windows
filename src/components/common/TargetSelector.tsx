import React from 'react';
import { ShieldCheck } from 'lucide-react';
import { AuthorizedTarget } from '../../types/assessment.types';
import { StatusBadge } from '../ui/StatusBadge';

export interface TargetSelectorProps {
  targets: AuthorizedTarget[];
  selectedTargetId: string;
  onChange: (targetId: string) => void;
  allowedTypes?: AuthorizedTarget['target_type'][];
  label?: string;
}

export const TargetSelector: React.FC<TargetSelectorProps> = ({
  targets,
  selectedTargetId,
  onChange,
  allowedTypes,
  label = 'Select Authorized & Verified Target',
}) => {
  const filteredTargets = allowedTypes
    ? targets.filter((t) => allowedTypes.includes(t.target_type))
    : targets;

  const selectedTarget = filteredTargets.find((t) => t.id === selectedTargetId);

  return (
    <div className="space-y-2">
      <label
        htmlFor="authorized-target-select"
        className="block text-xs font-medium text-[#F5F7FA]"
      >
        {label}
      </label>
      <div className="flex flex-col sm:flex-row sm:items-center gap-3">
        <select
          id="authorized-target-select"
          value={selectedTargetId}
          onChange={(e) => onChange(e.target.value)}
          className="flex-1 px-3.5 py-2 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs sm:text-sm text-[#F5F7FA] font-mono focus:outline-none focus:border-[#D6AE45]"
        >
          {filteredTargets.map((t) => (
            <option key={t.id} value={t.id}>
              [{t.verification_status}] {t.target_value} — {t.display_name} ({t.environment})
            </option>
          ))}
        </select>
        {selectedTarget && (
          <div className="flex items-center gap-2 text-xs text-[#A7B0BC] shrink-0">
            <ShieldCheck className="w-4 h-4 text-[#D6AE45]" aria-hidden="true" />
            <span>Method: {selectedTarget.verification_method}</span>
            <StatusBadge status={selectedTarget.verification_status} />
          </div>
        )}
      </div>
    </div>
  );
};
