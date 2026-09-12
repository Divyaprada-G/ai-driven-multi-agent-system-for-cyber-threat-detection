import React from 'react';
import { Activity, Key, UserX, AlertTriangle, ShieldAlert, ShieldCheck, Server, Users } from 'lucide-react';
import { StatCard } from '../common/StatCard';
import { SystemAgentAnalysis } from '../../types';

interface SystemMetricsBarProps {
  analysis: SystemAgentAnalysis;
}

export const SystemMetricsBar: React.FC<SystemMetricsBarProps> = ({ analysis }) => {
  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3" id="system-metrics-bar">
      <StatCard
        id="stat-sys-events-analyzed"
        title="Events Analyzed"
        value={analysis.totalSystemEvents.toLocaleString()}
        subtitle="Host & kernel logs"
        icon={Activity}
        variant="info"
      />
      <StatCard
        id="stat-sys-auth-events"
        title="Auth Events"
        value={analysis.authEventsCount.toLocaleString()}
        subtitle="Logon & credentials"
        icon={Key}
        variant="default"
      />
      <StatCard
        id="stat-sys-failed-logins"
        title="Failed Logins"
        value={analysis.failedLoginsCount.toLocaleString()}
        subtitle="Rejections & typos"
        icon={UserX}
        variant="warning"
      />
      <StatCard
        id="stat-sys-suspicious"
        title="Suspicious"
        value={analysis.suspiciousEventsCount.toLocaleString()}
        subtitle="Anomalies & spikes"
        icon={AlertTriangle}
        variant="warning"
      />
      <StatCard
        id="stat-sys-threats"
        title="Potential Threats"
        value={analysis.potentialThreatsCount.toLocaleString()}
        subtitle="Priv-esc & dumps"
        icon={ShieldAlert}
        variant="danger"
      />
      <StatCard
        id="stat-sys-confidence"
        title="Avg. Confidence"
        value={`${analysis.averageConfidence}%`}
        subtitle="Heuristic certainty"
        icon={ShieldCheck}
        variant="emerald"
      />
      <StatCard
        id="stat-sys-hosts"
        title="Hosts Monitored"
        value={analysis.uniqueHostsCount}
        subtitle="Endpoints & servers"
        icon={Server}
        variant="default"
      />
      <StatCard
        id="stat-sys-users"
        title="Users Tracked"
        value={analysis.uniqueUsersCount}
        subtitle="Accounts & services"
        icon={Users}
        variant="default"
      />
    </div>
  );
};
