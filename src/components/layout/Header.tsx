import React, { useState, useEffect } from 'react';
import { Menu, Activity, ShieldCheck, RefreshCw, Radio, Server } from 'lucide-react';
import { logRepository } from '../../services/logRepository';
import { NotificationCenterDropdown } from '../alerts/NotificationCenterDropdown';
import { SecurityAlert } from '../../types/alertIncident';
import { TelemetryStatusBadge } from '../telemetry/TelemetryStatusBadge';
import { realtimeTelemetryStream } from '../../services/telemetry/realtimeTelemetryStream';
import { UserRoleDropdown } from './UserRoleDropdown';

interface HeaderProps {
  onOpenMobileMenu: () => void;
  onRefresh?: () => void;
  isRefreshing?: boolean;
  onSelectAlert?: (alert: SecurityAlert) => void;
  onNavigateToAlerts?: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenMobileMenu,
  onRefresh,
  isRefreshing = false,
  onSelectAlert,
  onNavigateToAlerts
}) => {
  const [collectorHealth, setCollectorHealth] = useState<any>(realtimeTelemetryStream.getCollectorHealth());

  useEffect(() => {
    const unsub = realtimeTelemetryStream.onCollectorHealth((health) => {
      setCollectorHealth(health);
    });
    return () => unsub();
  }, []);

  const activeCollectors = collectorHealth?.activeCollectorsCount ?? 0;
  const totalCollectors = collectorHealth?.totalCollectors ?? 3;

  return (
    <header
      id="app-header"
      className="sticky top-0 z-30 bg-slate-950/90 backdrop-blur-md border-b border-slate-800/80 px-4 lg:px-8 py-3.5"
    >
      <div className="flex items-center justify-between gap-4">
        {/* Left: Mobile Toggle & Project Title / Subtitle */}
        <div className="flex items-center gap-3">
          <button
            id="btn-open-mobile-menu"
            onClick={onOpenMobileMenu}
            className="p-2 -ml-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-900 lg:hidden"
            aria-label="Open Navigation Menu"
          >
            <Menu className="w-5 h-5" />
          </button>

          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-base sm:text-lg font-extrabold tracking-tight text-white uppercase font-sans">
                AI DRIVEN MULTI-AGENT{' '}
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400">
                  CYBER THREAT DETECTION
                </span>
              </h1>
            </div>
            <p className="text-[11px] sm:text-xs text-slate-400 hidden sm:block">
              Real-time intelligent monitoring, correlation and threat analysis
            </p>
          </div>
        </div>

        {/* Right: Verified Telemetry Status Badge, RBAC User, & Collectors Status */}
        <div className="flex items-center gap-2.5 sm:gap-4">
          {/* User Role & Session Selector */}
          <UserRoleDropdown />

          {/* Notification Center */}
          <NotificationCenterDropdown
            onSelectAlert={onSelectAlert}
            onNavigateToAlerts={onNavigateToAlerts}
          />

          {/* Verified Telemetry Status Badge: LIVE / CONNECTING / DISCONNECTED / SIMULATION / ERROR */}
          <TelemetryStatusBadge />

          {/* Verified Host Collectors Status */}
          <div className="hidden lg:flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
            <Server className={`w-3.5 h-3.5 ${activeCollectors > 0 ? 'text-emerald-400 animate-pulse' : 'text-slate-500'}`} />
            <span className="text-slate-400">Collectors:</span>
            <span className={activeCollectors > 0 ? 'text-emerald-400 font-semibold' : 'text-slate-400 font-semibold'}>
              {activeCollectors}/{totalCollectors} ACTIVE
            </span>
          </div>

          {/* Refresh trigger */}
          {onRefresh && (
            <button
              id="btn-refresh-telemetry"
              onClick={onRefresh}
              disabled={isRefreshing}
              className="p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:border-slate-700 transition-colors disabled:opacity-50"
              title="Refresh Telemetry Metrics"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          )}
        </div>
      </div>
    </header>
  );
};


