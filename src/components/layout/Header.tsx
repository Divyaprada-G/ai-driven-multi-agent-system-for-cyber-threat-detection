import React, { useState, useEffect } from 'react';
import { Menu, Activity, ShieldCheck, RefreshCw, Radio } from 'lucide-react';
import { logRepository } from '../../services/logRepository';
import { NotificationCenterDropdown } from '../alerts/NotificationCenterDropdown';
import { SecurityAlert } from '../../types/alertIncident';

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
  const [hasRealData, setHasRealData] = useState(logRepository.hasRealData());
  const [totalEvents, setTotalEvents] = useState(logRepository.getStats().totalEvents);

  useEffect(() => {
    const update = () => {
      setHasRealData(logRepository.hasRealData());
      setTotalEvents(logRepository.getStats().totalEvents);
    };
    return logRepository.subscribe(update);
  }, []);

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

        {/* Right: Telemetry Mode Badge & SOC Pipeline Status */}
        <div className="flex items-center gap-2.5 sm:gap-4">
          {/* Notification Center */}
          <NotificationCenterDropdown
            onSelectAlert={onSelectAlert}
            onNavigateToAlerts={onNavigateToAlerts}
          />

          {hasRealData ? (
            <div
              id="badge-real-data"
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-cyan-500/40 bg-cyan-950/40 text-cyan-300 text-xs font-mono font-bold shadow-[0_0_10px_rgba(6,182,212,0.15)]"
            >
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
              <span className="w-2 h-2 rounded-full bg-cyan-400 absolute" />
              <span className="ml-1.5 tracking-wider">REAL DATA ({totalEvents})</span>
            </div>
          ) : (
            <div
              id="badge-demo-mode"
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-amber-500/40 bg-amber-950/40 text-amber-300 text-xs font-mono font-bold shadow-[0_0_10px_rgba(245,158,11,0.15)]"
            >
              <span className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
              <span className="w-2 h-2 rounded-full bg-amber-400 absolute" />
              <span className="ml-1.5 tracking-wider">DEMO MODE</span>
            </div>
          )}

          {/* Live SOC Pipeline Status */}
          <div className="hidden md:flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs font-mono text-slate-300">
            <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />
            <span className="text-slate-400">SOC Pipeline:</span>
            <span className="text-emerald-400 font-semibold">{hasRealData ? 'REAL INGESTION' : 'SIMULATED'}</span>
          </div>

          {/* Refresh simulated trigger */}
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

