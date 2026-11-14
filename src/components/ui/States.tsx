import React from 'react';
import { AlertCircle, Inbox } from 'lucide-react';
import { Button } from './Button';

export const EmptyState: React.FC<{
  title: string;
  description: string;
  actionLabel?: string;
  onAction?: () => void;
}> = ({ title, description, actionLabel, onAction }) => (
  <div className="p-8 text-center bg-[#101318]/60 border border-[#29313B] rounded-lg">
    <Inbox className="w-8 h-8 text-[#737E8C] mx-auto mb-3" aria-hidden="true" />
    <h3 className="text-sm font-semibold text-[#F5F7FA]">{title}</h3>
    <p className="text-xs text-[#A7B0BC] max-w-md mx-auto mt-1 leading-relaxed">{description}</p>
    {actionLabel && onAction && (
      <div className="mt-4">
        <Button variant="primary" size="sm" onClick={onAction}>
          {actionLabel}
        </Button>
      </div>
    )}
  </div>
);

export const ErrorState: React.FC<{
  title?: string;
  message: string;
  onRetry?: () => void;
}> = ({ title = 'Operation Blocked or Unavailable', message, onRetry }) => (
  <div className="p-4 bg-[#F05252]/10 border border-[#F05252]/30 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-3">
    <div className="flex items-start gap-3">
      <AlertCircle className="w-5 h-5 text-[#F05252] shrink-0 mt-0.5" aria-hidden="true" />
      <div>
        <h4 className="text-xs sm:text-sm font-semibold text-[#F5F7FA]">{title}</h4>
        <p className="text-xs text-[#A7B0BC] mt-0.5">{message}</p>
      </div>
    </div>
    {onRetry && (
      <Button variant="secondary" size="sm" onClick={onRetry}>
        Retry
      </Button>
    )}
  </div>
);

export const SkeletonLoader: React.FC<{ rows?: number }> = ({ rows = 3 }) => (
  <div className="space-y-2.5" aria-busy="true" aria-label="Loading data">
    {Array.from({ length: rows }).map((_, i) => (
      <div
        key={i}
        className="h-11 bg-[#141920] border border-[#29313B] rounded-lg animate-pulse"
      />
    ))}
  </div>
);
