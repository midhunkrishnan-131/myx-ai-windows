import React from 'react';

export interface CardProps {
  title?: string;
  subtitle?: string;
  headerAction?: React.ReactNode;
  footer?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  noPadding?: boolean;
}

export const Card: React.FC<CardProps> = ({
  title,
  subtitle,
  headerAction,
  footer,
  children,
  className = '',
  noPadding = false,
}) => {
  return (
    <section
      className={`bg-[#141920] border border-[#29313B] rounded-lg overflow-hidden ${className}`}
    >
      {(title || subtitle || headerAction) && (
        <div className="px-5 py-4 border-b border-[#29313B] flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
          <div>
            {title && (
              <h2 className="text-sm sm:text-base font-semibold text-[#F5F7FA] tracking-tight">
                {title}
              </h2>
            )}
            {subtitle && (
              <p className="text-xs text-[#A7B0BC] mt-0.5 leading-relaxed">{subtitle}</p>
            )}
          </div>
          {headerAction && <div className="shrink-0 flex items-center gap-2">{headerAction}</div>}
        </div>
      )}
      <div className={noPadding ? '' : 'p-5'}>{children}</div>
      {footer && (
        <div className="px-5 py-3 bg-[#101318] border-t border-[#29313B] text-xs text-[#A7B0BC]">
          {footer}
        </div>
      )}
    </section>
  );
};
