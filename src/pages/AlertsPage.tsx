import React, { useState, useEffect } from 'react';
import { Bell, Send, Check, AlertTriangle, Radio, ExternalLink } from 'lucide-react';
import { SecurityAlert, AlertStatus } from '../types';
import { alertService } from '../services/alertService';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';

export const AlertsPage: React.FC = () => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [notificationFeedback, setNotificationFeedback] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      const data = await alertService.getAlerts();
      setAlerts(data);
    }
    load();
  }, []);

  const handleUpdateStatus = async (alertId: string, newStatus: AlertStatus) => {
    await alertService.updateAlertStatus(alertId, newStatus);
    const refreshed = await alertService.getAlerts();
    setAlerts(refreshed);
  };

  const handleTriggerN8n = async (alertId: string) => {
    const res = await alertService.triggerN8nAutomation(alertId);
    setNotificationFeedback(res.message);
    const refreshed = await alertService.getAlerts();
    setAlerts(refreshed);
    setTimeout(() => setNotificationFeedback(null), 6000);
  };

  return (
    <div className="space-y-6" id="page-alerts">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest">
            Dispatch & Automated Notification Layer
          </span>
        </div>
        <h2 className="text-xl font-bold text-white tracking-tight">
          Security Alerts & Webhook Automation
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          Real-time alert dispatching layer designed to relay prioritized threats to notification webhooks, on-call paging, Slack channels, and upstream n8n workflow playbooks.
        </p>
      </div>

      {/* Notification Feedback Banner */}
      {notificationFeedback && (
        <div className="p-3.5 bg-emerald-950/70 border border-emerald-700/80 rounded-xl text-xs font-mono text-emerald-300 flex items-center justify-between gap-3 animate-fade-in">
          <div className="flex items-center gap-2">
            <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
            <span>{notificationFeedback}</span>
          </div>
          <button
            onClick={() => setNotificationFeedback(null)}
            className="text-slate-400 hover:text-white"
          >
            Dismiss
          </button>
        </div>
      )}

      {/* 14. ALERTS TABLE */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <Bell className="w-4 h-4 text-cyan-400" />
              Active Alert Stream
            </h3>
            <p className="text-xs text-slate-400">
              Correlated alerts mapped to n8n automated response triggers.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">
            Total Alerts: {alerts.length}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Alert ID</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Threat Name</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Notification Status</th>
                <th className="py-3 px-4 text-right">n8n Automation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {alerts.map(alert => (
                <tr
                  key={alert.alertId}
                  id={`row-alert-${alert.alertId.toLowerCase()}`}
                  className="hover:bg-slate-800/40 transition-colors"
                >
                  <td className="py-3 px-4 font-bold text-cyan-400">
                    {alert.alertId}
                  </td>

                  <td className="py-3 px-4 text-slate-400">
                    {alert.timestamp}
                  </td>

                  <td className="py-3 px-4 font-sans font-medium text-slate-100 max-w-[200px] truncate">
                    {alert.threat}
                  </td>

                  <td className="py-3 px-4">
                    <SeverityBadge severity={alert.severity} />
                  </td>

                  <td className="py-3 px-4 text-slate-300 max-w-[160px] truncate">
                    {alert.source}
                  </td>

                  <td className="py-3 px-4 font-bold text-rose-400">
                    {alert.riskScore}/100
                  </td>

                  <td className="py-3 px-4">
                    <select
                      id={`select-alert-status-${alert.alertId.toLowerCase()}`}
                      value={alert.status}
                      onChange={e => handleUpdateStatus(alert.alertId, e.target.value as AlertStatus)}
                      className="text-[11px] font-mono bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 focus:outline-none focus:border-cyan-500"
                    >
                      <option value="UNACKNOWLEDGED">UNACKNOWLEDGED</option>
                      <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                      <option value="RESOLVED">RESOLVED</option>
                      <option value="SUPPRESSED">SUPPRESSED</option>
                    </select>
                  </td>

                  <td className="py-3 px-4">
                    <StatusBadge status={alert.notificationStatus} type="alert" />
                  </td>

                  <td className="py-3 px-4 text-right">
                    <button
                      id={`btn-n8n-trigger-${alert.alertId.toLowerCase()}`}
                      onClick={() => handleTriggerN8n(alert.alertId)}
                      className="px-2.5 py-1.5 bg-cyan-950/60 hover:bg-cyan-900 border border-cyan-800/80 text-cyan-300 rounded-lg text-xs font-mono transition-colors inline-flex items-center gap-1.5 shadow-sm"
                      title="Dispatch automated n8n webhook"
                    >
                      <Send className="w-3.5 h-3.5" />
                      <span>Trigger n8n</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
