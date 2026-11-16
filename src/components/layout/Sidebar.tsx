import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  Globe,
  Network,
  Wifi,
  MonitorCheck,
  Link2,
  Lock,
  Server,
  ShieldAlert,
  Bot,
  FilePenLine,
  History,
  FileCheck2,
  Blocks,
  Users,
  Settings,
  KeyRound,
  Shield,
  Radio,
  ChevronLeft,
  ChevronRight,
} from 'lucide-react';
import { BRAND_CONFIG } from '../../config/brand.config';
import { NAVIGATION_CATALOG } from './navigationCatalog';
import { useRBAC } from '../../hooks/useRBAC';

const ICON_MAP: Record<string, React.ReactNode> = {
  '/dashboard': <LayoutDashboard className="w-4 h-4 shrink-0" />,
  '/assessments/website': <Globe className="w-4 h-4 shrink-0" />,
  '/assessments/network': <Network className="w-4 h-4 shrink-0" />,
  '/auditors/wifi': <Wifi className="w-4 h-4 shrink-0" />,
  '/auditors/wifi-lab': <KeyRound className="w-4 h-4 shrink-0" />,
  '/auditors/windows': <MonitorCheck className="w-4 h-4 shrink-0" />,
  '/intelligence/linkguard': <Link2 className="w-4 h-4 shrink-0" />,
  '/analyzers/ssl-tls': <Lock className="w-4 h-4 shrink-0" />,
  '/analyzers/dns': <Server className="w-4 h-4 shrink-0" />,
  '/intelligence/network-trust': <Radio className="w-4 h-4 shrink-0 text-emerald-400" />,
  '/findings': <ShieldAlert className="w-4 h-4 shrink-0" />,
  '/ai/analyst': <Bot className="w-4 h-4 shrink-0" />,
  '/reports/studio': <FilePenLine className="w-4 h-4 shrink-0" />,
  '/assessments/history': <History className="w-4 h-4 shrink-0" />,
  '/reports': <FileCheck2 className="w-4 h-4 shrink-0" />,
  '/integrations': <Blocks className="w-4 h-4 shrink-0" />,
  '/admin/users': <Users className="w-4 h-4 shrink-0" />,
  '/settings': <Settings className="w-4 h-4 shrink-0" />,
  '/account/security': <KeyRound className="w-4 h-4 shrink-0" />,
};

export const Sidebar: React.FC<{
  collapsedOnTablet: boolean;
  onToggleTabletRail: () => void;
}> = ({ collapsedOnTablet, onToggleTabletRail }) => {
  const { role } = useRBAC();

  const groups: Array<typeof NAVIGATION_CATALOG[number]['group']> = [
    'Core & Posture',
    'Assessments & Auditors',
    'Intelligence & Analyzers',
    'Findings & AI Copilot',
    'Administration & Account',
  ];

  return (
    <aside
      aria-label="Primary Sidebar Navigation"
      className={`hidden md:flex flex-col bg-[#080A0D] border-r border-[#29313B] shrink-0 transition-all duration-150 ${
        collapsedOnTablet ? 'md:w-16 lg:w-64' : 'w-64'
      }`}
    >
      {/* Brand Lockup */}
      <div className="min-h-16 py-2.5 px-4 border-b border-[#29313B] flex items-center justify-between gap-2">
        <div className="flex items-center gap-3 min-w-0">
          <div className="w-11 h-11 rounded-lg bg-[#101318] border border-[#D6AE45]/40 p-1 flex items-center justify-center shrink-0 shadow-sm">
            <img
              src={BRAND_CONFIG.BRAND_LOGO_URL}
              alt={`${BRAND_CONFIG.BRAND_PRODUCT_NAME} ${BRAND_CONFIG.BRAND_EDITION_NAME} Logo`}
              className="w-full h-full object-contain"
            />
          </div>
          <div className={`${collapsedOnTablet ? 'md:hidden lg:block' : 'block'} truncate`}>
            <div className="text-sm font-bold text-[#F5F7FA] tracking-tight truncate">
              {BRAND_CONFIG.BRAND_PRODUCT_NAME}{' '}
              <span className="text-xs font-normal text-[#D6AE45]">
                {BRAND_CONFIG.BRAND_EDITION_NAME}
              </span>
            </div>
            <div className="text-[11px] text-[#A7B0BC] truncate">
              by {BRAND_CONFIG.BRAND_AUTHOR}
            </div>
          </div>
        </div>
        <button
          type="button"
          onClick={onToggleTabletRail}
          aria-label="Toggle tablet sidebar rail"
          className="hidden md:inline-flex lg:hidden p-1.5 rounded text-[#A7B0BC] hover:text-[#F5F7FA] hover:bg-[#1B222B]"
        >
          {collapsedOnTablet ? (
            <ChevronRight className="w-4 h-4" />
          ) : (
            <ChevronLeft className="w-4 h-4" />
          )}
        </button>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 overflow-y-auto py-3 px-2.5 space-y-5">
        {groups.map((groupName) => {
          const items = NAVIGATION_CATALOG.filter((item) => item.group === groupName);
          return (
            <div key={groupName}>
              <div
                className={`px-2.5 mb-1.5 text-[11px] font-medium text-[#737E8C] truncate ${
                  collapsedOnTablet ? 'md:hidden lg:block' : 'block'
                }`}
              >
                {groupName}
              </div>
              <div className="space-y-0.5">
                {items.map((item) => {
                  const isPermitted = item.allowedRoles.includes(role);
                  return (
                    <NavLink
                      key={item.path}
                      to={item.path}
                      end
                      title={`${item.label}${!isPermitted ? ` (Requires ${item.allowedRoles.join('/')})` : ''}`}
                      className={({ isActive }) =>
                        `flex items-center justify-between gap-2.5 px-2.5 py-2 rounded-md text-xs font-medium transition-colors whitespace-nowrap ${
                          isActive
                            ? 'bg-[#D6AE45]/15 text-[#E7C66A] border-l-4 border-[#D6AE45]'
                            : isPermitted
                            ? 'text-[#A7B0BC] hover:text-[#F5F7FA] hover:bg-[#1B222B]'
                            : 'text-[#737E8C] hover:text-[#A7B0BC] hover:bg-[#141920]/60'
                        }`
                      }
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        {ICON_MAP[item.path]}
                        <span
                          className={`truncate ${
                            collapsedOnTablet ? 'md:hidden lg:inline' : 'inline'
                          }`}
                        >
                          {item.label}
                        </span>
                      </div>
                      {!isPermitted && (
                        <span
                          className={`text-[10px] font-mono text-[#737E8C] ${
                            collapsedOnTablet ? 'md:hidden lg:inline' : 'inline'
                          }`}
                        >
                          RBAC
                        </span>
                      )}
                    </NavLink>
                  );
                })}
              </div>
            </div>
          );
        })}
      </nav>

      {/* Footer Attribution */}
      <div
        className={`p-3.5 border-t border-[#29313B] text-[11px] text-[#737E8C] ${
          collapsedOnTablet ? 'md:hidden lg:block' : 'block'
        }`}
      >
        <div className="font-medium text-[#A7B0BC] truncate">{BRAND_CONFIG.BRAND_FULL_TITLE}</div>
        <div className="mt-0.5 truncate">
          {BRAND_CONFIG.BRAND_TAGLINE} · Windows 10/11 Scope
        </div>
      </div>
    </aside>
  );
};
