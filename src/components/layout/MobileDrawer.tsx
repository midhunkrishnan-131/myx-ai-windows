import React from 'react';
import { NavLink } from 'react-router-dom';
import { Shield, X } from 'lucide-react';
import { BRAND_CONFIG } from '../../config/brand.config';
import { NAVIGATION_CATALOG } from './navigationCatalog';
import { useRBAC } from '../../hooks/useRBAC';

export const MobileDrawer: React.FC<{
  isOpen: boolean;
  onClose: () => void;
}> = ({ isOpen, onClose }) => {
  const { role } = useRBAC();

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 md:hidden flex">
      <div
        className="fixed inset-0 bg-black/70 backdrop-blur-xs"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Mobile Navigation Menu"
        className="relative w-72 max-w-[85vw] bg-[#080A0D] border-r border-[#29313B] flex flex-col h-full z-10"
      >
        <div className="h-16 px-4 border-b border-[#29313B] flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <img
              src={BRAND_CONFIG.BRAND_LOGO_URL}
              alt={`${BRAND_CONFIG.BRAND_PRODUCT_NAME} Logo`}
              className="w-9 h-9 object-contain shrink-0"
            />
            <div>
              <div className="text-sm font-bold text-[#F5F7FA]">
                {BRAND_CONFIG.BRAND_PRODUCT_NAME}{' '}
                <span className="text-xs font-normal text-[#D6AE45]">
                  {BRAND_CONFIG.BRAND_EDITION_NAME}
                </span>
              </div>
              <div className="text-[10px] text-[#A7B0BC]">by {BRAND_CONFIG.BRAND_AUTHOR}</div>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close navigation menu"
            className="p-2 rounded text-[#A7B0BC] hover:text-[#F5F7FA] hover:bg-[#1B222B] min-h-[44px] min-w-[44px] flex items-center justify-center"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <nav className="flex-1 overflow-y-auto p-3 space-y-1">
          {NAVIGATION_CATALOG.map((item) => {
            const isPermitted = item.allowedRoles.includes(role);
            return (
              <NavLink
                key={item.path}
                to={item.path}
                end
                onClick={onClose}
                className={({ isActive }) =>
                  `flex items-center justify-between px-3 py-2.5 rounded-md text-xs font-medium min-h-[44px] ${
                    isActive
                      ? 'bg-[#D6AE45]/15 text-[#F5F7FA] border-l-4 border-[#D6AE45]'
                      : isPermitted
                      ? 'text-[#A7B0BC] hover:text-[#F5F7FA] hover:bg-[#1B222B]'
                      : 'text-[#737E8C]'
                  }`
                }
              >
                <span>{item.label}</span>
                {!isPermitted && <span className="text-[10px] font-mono">RBAC</span>}
              </NavLink>
            );
          })}
        </nav>

        <div className="p-3.5 border-t border-[#29313B] text-xs text-[#737E8C]">
          {BRAND_CONFIG.BRAND_FULL_TITLE} · {BRAND_CONFIG.BRAND_TAGLINE}
        </div>
      </div>
    </div>
  );
};
