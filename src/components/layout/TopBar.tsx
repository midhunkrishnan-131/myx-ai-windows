import React, { useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { Menu, ShieldCheck, Download, LogOut } from 'lucide-react';
import { BRAND_CONFIG } from '../../config/brand.config';
import { NAVIGATION_CATALOG } from './navigationCatalog';
import { useAuth } from '../../hooks/useAuth';
import { UserRole } from '../../types/auth.types';
import { downloadAntigravityProjectZip } from '../../utils/downloadProjectZip';

export const TopBar: React.FC<{
  onOpenMobileMenu: () => void;
}> = ({ onOpenMobileMenu }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, switchRoleForDemo, logoutCurrentSession } = useAuth();
  const [downloadingZip, setDownloadingZip] = useState(false);

  const handleSignOut = () => {
    logoutCurrentSession();
    navigate('/login');
  };

  const activeNav =
    NAVIGATION_CATALOG.find((item) => location.pathname.startsWith(item.path)) ||
    NAVIGATION_CATALOG[0];

  const handleZipDownload = async () => {
    if (downloadingZip) return;
    setDownloadingZip(true);
    try {
      await downloadAntigravityProjectZip();
    } finally {
      setDownloadingZip(false);
    }
  };

  return (
    <header className="h-14 px-4 sm:px-6 bg-[#101318] border-b border-[#29313B] flex items-center justify-between gap-4 shrink-0">
      {/* Zone 1: Mobile Menu Trigger + Breadcrumb Trail */}
      <div className="flex items-center gap-3 min-w-0">
        <button
          type="button"
          onClick={onOpenMobileMenu}
          aria-label="Open navigation drawer"
          className="md:hidden p-2 -ml-2 rounded-lg text-[#A7B0BC] hover:text-[#F5F7FA] hover:bg-[#1B222B] min-h-[44px] min-w-[44px] flex items-center justify-center shrink-0"
        >
          <Menu className="w-5 h-5" />
        </button>
        <div className="flex items-center gap-2 text-xs sm:text-sm truncate">
          <img
            src={BRAND_CONFIG.BRAND_LOGO_URL}
            alt={BRAND_CONFIG.BRAND_PRODUCT_NAME}
            className="w-6 h-6 object-contain shrink-0"
          />
          <span className="font-semibold text-[#D6AE45] whitespace-nowrap shrink-0">
            {BRAND_CONFIG.BRAND_PRODUCT_NAME}
          </span>
          <span className="text-[#737E8C]" aria-hidden="true">
            /
          </span>
          <span className="text-[#A7B0BC] hidden sm:inline whitespace-nowrap shrink-0">
            {activeNav.group}
          </span>
          <span className="text-[#737E8C] hidden sm:inline" aria-hidden="true">
            /
          </span>
          <span className="text-[#F5F7FA] font-medium truncate">{activeNav.label}</span>
        </div>
      </div>

      {/* Zone 2: Antigravity ZIP Export (ADMIN Only), RBAC Role Selector & Account Security Action */}
      <div className="flex items-center gap-2.5 shrink-0">
        {user?.role === 'ADMIN' && (
          <button
            type="button"
            onClick={handleZipDownload}
            disabled={downloadingZip}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#141920] hover:bg-[#1B222B] border border-[#D6AE45]/60 text-[#D6AE45] rounded-lg text-xs font-semibold transition-colors whitespace-nowrap shrink-0 cursor-pointer disabled:opacity-60"
            title="Download Verified Project ZIP Archive (PK\x03\x04) for Google Antigravity (ADMIN Only)"
          >
            <Download className="w-3.5 h-3.5" aria-hidden="true" />
            <span className="hidden sm:inline">
              {downloadingZip ? 'Preparing ZIP…' : 'Download Antigravity ZIP'}
            </span>
            <span className="sm:hidden">ZIP</span>
          </button>
        )}

        <div className="flex items-center gap-1.5">
          <label htmlFor="rbac-role-select" className="text-xs text-[#A7B0BC] hidden lg:inline">
            Active RBAC Role:
          </label>
          <select
            id="rbac-role-select"
            aria-label="Active RBAC Role"
            value={user?.role || 'ADMIN'}
            onChange={(e) => switchRoleForDemo(e.target.value as UserRole)}
            className="px-2.5 py-1.5 bg-[#141920] border border-[#29313B] rounded-md text-xs font-mono text-[#F5F7FA] focus:outline-none focus:border-[#D6AE45]"
          >
            <option value="ADMIN">Role: ADMIN</option>
            <option value="SECURITY_ANALYST">Role: SECURITY_ANALYST</option>
            <option value="VIEWER">Role: VIEWER (Read-Only)</option>
          </select>
        </div>

        <Link
          to="/account/security"
          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#D6AE45] hover:bg-[#E7C66A] text-[#080A0D] rounded-lg text-xs font-semibold transition-colors whitespace-nowrap shrink-0"
        >
          <ShieldCheck className="w-3.5 h-3.5" aria-hidden="true" />
          <span className="hidden sm:inline">{user?.full_name || 'Midhun Krishnan'}</span>
          <span className="sm:hidden">2FA</span>
        </Link>

        <button
          type="button"
          onClick={handleSignOut}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 bg-[#141920] hover:bg-[#1B222B] border border-[#29313B] text-[#A7B0BC] hover:text-[#F05252] rounded-lg text-xs font-medium transition-colors whitespace-nowrap shrink-0 cursor-pointer"
          title="Sign out of security session"
        >
          <LogOut className="w-3.5 h-3.5" aria-hidden="true" />
          <span className="hidden sm:inline">Sign Out</span>
        </button>
      </div>
    </header>
  );
};
