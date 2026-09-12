import React, { useState, useEffect, useRef } from 'react';
import { Bell, ShieldAlert, Check, ExternalLink, CheckCheck, X } from 'lucide-react';
import { SecurityAlert } from '../../types/alertIncident';
import { alertManager } from '../../services/alertIncident/alertManager';

interface NotificationCenterDropdownProps {
  onSelectAlert?: (alert: SecurityAlert) => void;
  onNavigateToAlerts?: () => void;
}

export const NotificationCenterDropdown: React.FC<NotificationCenterDropdownProps> = ({
  onSelectAlert,
  onNavigateToAlerts
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [alerts, setAlerts] = useState<SecurityAlert[]>(alertManager.getAlerts());
  const [unreadCount, setUnreadCount] = useState<number>(alertManager.getUnreadCount());
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const update = () => {
      setAlerts(alertManager.getAlerts());
      setUnreadCount(alertManager.getUnreadCount());
    };
    return alertManager.subscribe(update);
  }, []);

  // Close on outside click
  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [isOpen]);

  const handleMarkAllRead = () => {
    alertManager.markAllAsRead();
  };

  const handleQuickAcknowledge = (e: React.MouseEvent, alertId: string) => {
    e.stopPropagation();
    alertManager.updateAlertStatus(alertId, 'ACKNOWLEDGED', 'Quick acknowledged from in-app notification center');
  };

  const handleSelect = (alert: SecurityAlert) => {
    alertManager.markAsRead(alert.id);
    setIsOpen(false);
    if (onSelectAlert) {
      onSelectAlert(alert);
    } else if (onNavigateToAlerts) {
      onNavigateToAlerts();
    }
  };

  const recentAlerts = alerts.slice(0, 6);

  return (
    <div className="relative" ref={containerRef}>
      {/* Bell Button */}
      <button
        id="btn-notification-center"
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        aria-label="In-App Security Alerts Notification Center"
        className="relative p-2 rounded-lg bg-slate-900 border border-slate-800 text-slate-300 hover:text-white hover:border-slate-700 transition-colors"
      >
        <Bell className="w-4 h-4 text-slate-300" />
        {unreadCount > 0 && (
          <span
            id="badge-unread-notifications"
            className="absolute -top-1 -right-1 px-1.5 py-0.2 min-w-[18px] text-[10px] font-mono font-bold rounded-full bg-rose-600 text-white border border-rose-500 shadow-sm flex items-center justify-center animate-pulse"
          >
            {unreadCount}
          </span>
        )}
      </button>

      {/* Dropdown Popover */}
      {isOpen && (
        <div
          id="dropdown-notifications"
          className="absolute right-0 mt-2 w-80 sm:w-96 bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl z-50 overflow-hidden font-sans"
        >
          {/* Header */}
          <div className="p-3.5 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="w-2 h-2 rounded-full bg-rose-500 animate-ping" />
              <span className="text-xs font-bold text-white tracking-tight uppercase font-mono">
                Security Notifications
              </span>
            </div>
            {unreadCount > 0 && (
              <button
                type="button"
                onClick={handleMarkAllRead}
                className="text-[11px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
              >
                <CheckCheck className="w-3.5 h-3.5" />
                <span>Mark all read</span>
              </button>
            )}
          </div>

          <div className="px-3.5 py-1.5 bg-amber-950/30 border-b border-amber-900/30 text-[10px] font-mono text-amber-300 flex items-center justify-between">
            <span>Simulated Telemetry Stream</span>
            <span>{alerts.length} Total Alerts</span>
          </div>

          {/* Alert List */}
          <div className="max-h-80 overflow-y-auto divide-y divide-slate-800/60">
            {recentAlerts.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 font-mono">
                No active security notifications.
              </div>
            ) : (
              recentAlerts.map(alert => {
                const priorityBadge =
                  alert.priority === 'P1'
                    ? 'text-rose-400 bg-rose-950/80 border-rose-800'
                    : alert.priority === 'P2'
                    ? 'text-orange-400 bg-orange-950/80 border-orange-800'
                    : alert.priority === 'P3'
                    ? 'text-amber-400 bg-amber-950/80 border-amber-800'
                    : 'text-blue-400 bg-blue-950/80 border-blue-800';

                return (
                  <div
                    key={alert.id}
                    onClick={() => handleSelect(alert)}
                    className={`p-3 transition-colors cursor-pointer hover:bg-slate-800/50 flex flex-col gap-1.5 ${
                      !alert.isRead ? 'bg-slate-900/90' : 'bg-slate-950/40 opacity-75'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-1.5">
                        <span className={`text-[10px] font-mono font-bold px-1.5 py-0.2 rounded border ${priorityBadge}`}>
                          {alert.priority}
                        </span>
                        <span className="text-[11px] font-mono font-bold text-cyan-400">
                          {alert.id}
                        </span>
                        {!alert.isRead && (
                          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                        )}
                      </div>
                      <span className="text-[10px] font-mono text-slate-500">
                        {alert.timestamp.includes(' ') ? alert.timestamp.split(' ')[1] : alert.timestamp}
                      </span>
                    </div>

                    <div className="text-xs font-semibold text-slate-200 line-clamp-1">
                      {alert.title}
                    </div>

                    <div className="flex items-center justify-between text-[11px] font-mono text-slate-400">
                      <span className="truncate max-w-[180px]">{alert.source}</span>
                      <div className="flex items-center gap-2">
                        <span className="text-rose-400 font-bold">{alert.riskScore}/100</span>
                        {alert.status === 'NEW' && (
                          <button
                            type="button"
                            onClick={e => handleQuickAcknowledge(e, alert.id)}
                            className="px-2 py-0.5 rounded bg-slate-800 hover:bg-cyan-600 hover:text-white text-slate-300 border border-slate-700 text-[10px] transition-colors"
                          >
                            Ack
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {/* Footer */}
          <div className="p-3 bg-slate-950 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
            <span className="text-[11px] text-slate-500">Stage 9 Multi-Agent SOC</span>
            {onNavigateToAlerts && (
              <button
                type="button"
                onClick={() => {
                  setIsOpen(false);
                  onNavigateToAlerts();
                }}
                className="text-cyan-400 hover:text-cyan-300 font-semibold flex items-center gap-1"
              >
                <span>View All Alerts &rarr;</span>
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
