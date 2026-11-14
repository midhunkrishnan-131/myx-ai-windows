import React, { useState } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { MobileDrawer } from './MobileDrawer';
import { ConnectionStatusBanner } from '../ui/ConnectionStatusBanner';
import { BRAND_CONFIG } from '../../config/brand.config';

export const AppShell: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [collapsedOnTablet, setCollapsedOnTablet] = useState(true);

  return (
    <div className="min-h-screen w-full bg-[#0B0D10] text-[#F5F7FA] flex overflow-x-hidden">
      <Sidebar
        collapsedOnTablet={collapsedOnTablet}
        onToggleTabletRail={() => setCollapsedOnTablet((prev) => !prev)}
      />
      <MobileDrawer isOpen={mobileMenuOpen} onClose={() => setMobileMenuOpen(false)} />

      <div className="flex-1 flex flex-col min-w-0">
        <TopBar onOpenMobileMenu={() => setMobileMenuOpen(true)} />
        <ConnectionStatusBanner />

        <main className="flex-1 p-4 sm:p-6 max-w-[1800px] w-full mx-auto space-y-6">
          {children}
        </main>

        <footer className="px-4 sm:px-6 py-4 border-t border-[#29313B] bg-[#080A0D] text-xs text-[#737E8C] flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            {BRAND_CONFIG.BRAND_FULL_TITLE} ({BRAND_CONFIG.BRAND_EDITION_NAME}) —{' '}
            {BRAND_CONFIG.BRAND_TAGLINE}
          </div>
          <div className="font-mono text-[11px]">
            Defensive Authorized Scope Only · Windows 10 & Windows 11 Local Host Support
          </div>
        </footer>
      </div>
    </div>
  );
};
