import React, { useState } from 'react';
import { Sidebar, NavPageId } from './Sidebar';
import { Header } from './Header';
import { SecurityAlert } from '../../types/alertIncident';

interface LayoutProps {
  currentPage: NavPageId;
  onNavigate: (page: NavPageId) => void;
  onRefresh?: () => void;
  isRefreshing?: boolean;
  onSelectAlert?: (alert: SecurityAlert) => void;
  onNavigateToAlerts?: () => void;
  children: React.ReactNode;
}

export const Layout: React.FC<LayoutProps> = ({
  currentPage,
  onNavigate,
  onRefresh,
  isRefreshing,
  onSelectAlert,
  onNavigateToAlerts,
  children
}) => {
  const [isMobileOpen, setIsMobileOpen] = useState(false);

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col antialiased selection:bg-cyan-500 selection:text-black">
      <div className="flex-1 flex w-full">
        <Sidebar
          currentPage={currentPage}
          onNavigate={onNavigate}
          isOpenMobile={isMobileOpen}
          onCloseMobile={() => setIsMobileOpen(false)}
        />

        <div className="flex-1 flex flex-col min-w-0 overflow-x-hidden">
          <Header
            onOpenMobileMenu={() => setIsMobileOpen(true)}
            onRefresh={onRefresh}
            isRefreshing={isRefreshing}
            onSelectAlert={onSelectAlert}
            onNavigateToAlerts={onNavigateToAlerts}
          />

          <main className="flex-1 p-4 sm:p-6 lg:p-8 max-w-7xl w-full mx-auto space-y-6">
            {children}
          </main>
        </div>
      </div>
    </div>
  );
};

