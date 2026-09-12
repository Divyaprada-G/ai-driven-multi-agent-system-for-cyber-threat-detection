import React from 'react';
import {
  LayoutDashboard,
  FileText,
  Network,
  Cpu,
  Globe,
  GitMerge,
  ShieldAlert,
  Activity,
  AlertOctagon,
  Bell,
  FileSpreadsheet,
  Settings,
  ShieldCheck,
  ChevronRight
} from 'lucide-react';

export type NavPageId =
  | 'dashboard'
  | 'log-explorer'
  | 'network-agent'
  | 'system-agent'
  | 'application-agent'
  | 'event-correlation'
  | 'threat-detection'
  | 'risk-analysis'
  | 'incidents'
  | 'alerts'
  | 'reports'
  | 'settings';

interface NavItem {
  id: NavPageId;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  badge?: string;
  badgeColor?: string;
}

const NAV_ITEMS: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'log-explorer', label: 'Log Explorer', icon: FileText, badge: 'Ingest' },
  { id: 'network-agent', label: 'Network Agent', icon: Network },
  { id: 'system-agent', label: 'System Agent', icon: Cpu },
  { id: 'application-agent', label: 'Application Agent', icon: Globe },
  { id: 'event-correlation', label: 'Event Correlation', icon: GitMerge, badge: 'AI' },
  { id: 'threat-detection', label: 'Threat Detection', icon: ShieldAlert, badge: 'ML' },
  { id: 'risk-analysis', label: 'Risk Analysis', icon: Activity },
  { id: 'incidents', label: 'Incidents', icon: AlertOctagon, badge: '4' },
  { id: 'alerts', label: 'Alerts', icon: Bell, badge: 'Active' },
  { id: 'reports', label: 'Reports', icon: FileSpreadsheet },
  { id: 'settings', label: 'Settings', icon: Settings }
];

interface SidebarProps {
  currentPage: NavPageId;
  onNavigate: (page: NavPageId) => void;
  isOpenMobile: boolean;
  onCloseMobile: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentPage,
  onNavigate,
  isOpenMobile,
  onCloseMobile
}) => {
  return (
    <>
      {/* Mobile Backdrop */}
      {isOpenMobile && (
        <div
          className="fixed inset-0 bg-black/70 backdrop-blur-sm z-40 lg:hidden"
          onClick={onCloseMobile}
        />
      )}

      {/* Sidebar Container */}
      <aside
        id="app-sidebar"
        className={`fixed lg:static top-0 left-0 bottom-0 z-40 w-64 bg-slate-950 border-r border-slate-800/80 flex flex-col justify-between transition-transform duration-200 ease-in-out ${
          isOpenMobile ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        {/* Brand & SOC Status */}
        <div>
          <div className="p-4 border-b border-slate-800/80 flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-500/20">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="font-bold text-sm tracking-tight text-white flex items-center gap-1.5">
                CYBER-SOC
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              </div>
              <div className="text-[10px] text-slate-400 font-mono tracking-wider uppercase">
                Multi-Agent Engine
              </div>
            </div>
          </div>

          {/* Navigation Links */}
          <nav className="p-3 space-y-1 overflow-y-auto max-h-[calc(100vh-210px)]">
            <div className="px-3 py-1.5 text-[10px] font-mono tracking-widest text-slate-500 uppercase">
              Operations Center
            </div>

            {NAV_ITEMS.map(item => {
              const Icon = item.icon;
              const isActive = currentPage === item.id;
              return (
                <button
                  key={item.id}
                  id={`nav-${item.id}`}
                  onClick={() => {
                    onNavigate(item.id);
                    onCloseMobile();
                  }}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all group ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 shadow-[inset_0_0_12px_rgba(6,182,212,0.1)]'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon
                      className={`w-4 h-4 transition-colors ${
                        isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-200'
                      }`}
                    />
                    <span className="truncate">{item.label}</span>
                  </div>

                  <div className="flex items-center gap-1.5">
                    {item.badge && (
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold ${
                          isActive
                            ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
                            : 'bg-slate-900 text-slate-400 border border-slate-800'
                        }`}
                      >
                        {item.badge}
                      </span>
                    )}
                    {isActive && <ChevronRight className="w-3.5 h-3.5 text-cyan-400" />}
                  </div>
                </button>
              );
            })}
          </nav>
        </div>

        {/* Footer Brand info as specified */}
        <div className="p-4 border-t border-slate-800/80 bg-slate-950/60">
          <div className="text-[11px] font-medium text-slate-200 font-mono tracking-tight truncate">
            AI Threat Detection Platform
          </div>
          <div className="text-[10px] text-slate-400 font-mono flex items-center justify-between mt-1">
            <span>Project Version: 1.0</span>
            <span className="text-emerald-400 font-semibold">SOC ONLINE</span>
          </div>
          <div className="mt-2 pt-2 border-t border-slate-900 text-[10px] text-slate-400 truncate">
            BE Major Project • 7th Semester
          </div>
        </div>
      </aside>
    </>
  );
};
