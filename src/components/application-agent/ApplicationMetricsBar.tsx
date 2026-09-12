import React from 'react';
import {
  Globe,
  Layers,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Users,
  Network,
  Activity,
  KeyRound
} from 'lucide-react';
import { ApplicationAgentAnalysis } from '../../types/application';

interface Props {
  analysis: ApplicationAgentAnalysis;
}

export const ApplicationMetricsBar: React.FC<Props> = ({ analysis }) => {
  const cards = [
    {
      id: 'metric-total-events',
      label: 'App Events Analyzed',
      value: analysis.totalApplicationEvents.toLocaleString(),
      subtext: 'Ingested HTTP/API logs',
      icon: Layers,
      color: 'text-indigo-600 dark:text-indigo-400',
      bg: 'bg-indigo-50 dark:bg-indigo-950/40 border-indigo-100 dark:border-indigo-900/40'
    },
    {
      id: 'metric-web-requests',
      label: 'Web Requests',
      value: analysis.webRequestsCount.toLocaleString(),
      subtext: 'Static & UI endpoints',
      icon: Globe,
      color: 'text-cyan-600 dark:text-cyan-400',
      bg: 'bg-cyan-50 dark:bg-cyan-950/40 border-cyan-100 dark:border-cyan-900/40'
    },
    {
      id: 'metric-api-requests',
      label: 'API Requests',
      value: analysis.apiRequestsCount.toLocaleString(),
      subtext: 'REST, v1/v2 & GraphQL',
      icon: Activity,
      color: 'text-blue-600 dark:text-blue-400',
      bg: 'bg-blue-50 dark:bg-blue-950/40 border-blue-100 dark:border-blue-900/40'
    },
    {
      id: 'metric-auth-events',
      label: 'Auth Events',
      value: analysis.authEventsCount.toLocaleString(),
      subtext: 'Logins & tokens',
      icon: KeyRound,
      color: 'text-purple-600 dark:text-purple-400',
      bg: 'bg-purple-50 dark:bg-purple-950/40 border-purple-100 dark:border-purple-900/40'
    },
    {
      id: 'metric-suspicious-requests',
      label: 'Suspicious Requests',
      value: analysis.suspiciousEventsCount.toLocaleString(),
      subtext: 'Anomalies & 4xx spikes',
      icon: AlertTriangle,
      color: 'text-amber-600 dark:text-amber-400',
      bg: 'bg-amber-50 dark:bg-amber-950/40 border-amber-100 dark:border-amber-900/40'
    },
    {
      id: 'metric-threats',
      label: 'Potential Threats',
      value: analysis.potentialThreatsCount.toLocaleString(),
      subtext: 'High-confidence findings',
      icon: ShieldAlert,
      color: 'text-rose-600 dark:text-rose-400',
      bg: 'bg-rose-50 dark:bg-rose-950/40 border-rose-100 dark:border-rose-900/40'
    },
    {
      id: 'metric-confidence',
      label: 'Average Confidence',
      value: `${Math.round(analysis.averageConfidence * 100)}%`,
      subtext: 'Evidence-based heuristic',
      icon: ShieldCheck,
      color: 'text-emerald-600 dark:text-emerald-400',
      bg: 'bg-emerald-50 dark:bg-emerald-950/40 border-emerald-100 dark:border-emerald-900/40'
    },
    {
      id: 'metric-users',
      label: 'Unique Users',
      value: analysis.uniqueUsersCount.toLocaleString(),
      subtext: 'Identified accounts',
      icon: Users,
      color: 'text-violet-600 dark:text-violet-400',
      bg: 'bg-violet-50 dark:bg-violet-950/40 border-violet-100 dark:border-violet-900/40'
    },
    {
      id: 'metric-source-ips',
      label: 'Unique Source IPs',
      value: analysis.uniqueSourceIpsCount.toLocaleString(),
      subtext: 'Observed client origins',
      icon: Network,
      color: 'text-teal-600 dark:text-teal-400',
      bg: 'bg-teal-50 dark:bg-teal-950/40 border-teal-100 dark:border-teal-900/40'
    }
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 xl:grid-cols-9 gap-3">
      {cards.map(card => {
        const Icon = card.icon;
        return (
          <div
            key={card.id}
            id={card.id}
            className={`p-3.5 rounded-xl border transition-all duration-200 shadow-sm hover:shadow ${card.bg}`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs font-semibold text-slate-600 dark:text-slate-400 truncate">
                {card.label}
              </span>
              <Icon className={`w-4 h-4 shrink-0 ${card.color}`} />
            </div>
            <div className="text-xl font-bold tracking-tight text-slate-900 dark:text-slate-100">
              {card.value}
            </div>
            <div className="text-[10px] text-slate-500 dark:text-slate-400 truncate mt-0.5">
              {card.subtext}
            </div>
          </div>
        );
      })}
    </div>
  );
};
