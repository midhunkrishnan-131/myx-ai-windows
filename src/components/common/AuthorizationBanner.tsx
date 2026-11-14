import React from 'react';
import { Shield } from 'lucide-react';

export const AuthorizationBanner: React.FC<{
  scopeNote: string;
}> = ({ scopeNote }) => {
  return (
    <div className="px-4 py-3 bg-[#101318] border border-[#29313B] rounded-lg flex items-start gap-3 text-xs text-[#A7B0BC]">
      <Shield className="w-4 h-4 text-[#D6AE45] shrink-0 mt-0.5" aria-hidden="true" />
      <div className="leading-relaxed">
        <span className="font-semibold text-[#F5F7FA]">
          Defensive & Authorized Scope Enforcement:
        </span>{' '}
        {scopeNote}
      </div>
    </div>
  );
};
