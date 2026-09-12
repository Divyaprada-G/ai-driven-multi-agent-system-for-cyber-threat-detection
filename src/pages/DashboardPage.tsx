import React from 'react';
import {
  Activity,
  AlertTriangle,
  Flame,
  ShieldAlert,
  Network,
  Server,
  Globe,
  TrendingUp,
  Radio
} from 'lucide-react';
import { StatCard } from '../components/common/StatCard';
import { AgentStatusCard } from '../components/common/AgentStatusCard';
import { EventsOverTimeChart } from '../components/charts/EventsOverTimeChart';
import { ThreatSeverityChart } from '../components/charts/ThreatSeverityChart';
import { EventsBySourceChart } from '../components/charts/EventsBySourceChart';
import { AgentActivityChart } from '../components/charts/AgentActivityChart';
import { ThreatCategoriesChart } from '../components/charts/ThreatCategoriesChart';
import { RecentEventsTable } from '../components/tables/RecentEventsTable';
import {
  DashboardMetrics,
  AgentStatusInfo,
  TimeSeriesPoint,
  SeverityDistributionPoint,
  SourceDistributionPoint,
  AgentActivityPoint,
  ThreatCategoryPoint
} from '../types';
import { NavPageId } from '../components/layout/Sidebar';
import { RecentEventItem } from '../components/tables/RecentEventsTable';

interface DashboardPageProps {
  metrics: DashboardMetrics;
  agents: AgentStatusInfo[];
  eventsOverTime: TimeSeriesPoint[];
  severityDistribution: SeverityDistributionPoint[];
  eventsBySource: SourceDistributionPoint[];
  agentActivity: AgentActivityPoint[];
  threatCategories: ThreatCategoryPoint[];
  recentEvents: RecentEventItem[];
  onNavigate: (page: NavPageId) => void;
  onToggleAgentStatus?: (agentId: string) => void;
}

export const DashboardPage: React.FC<DashboardPageProps> = ({
  metrics,
  agents,
  eventsOverTime,
  severityDistribution,
  eventsBySource,
  agentActivity,
  threatCategories,
  recentEvents,
  onNavigate,
  onToggleAgentStatus
}) => {
  return (
    <div className="space-y-6" id="page-dashboard">
      {/* Top Banner Notice: Architecture Overview */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 border border-slate-800 rounded-xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-xs font-mono uppercase tracking-widest text-cyan-400 font-semibold">
              Live SOC Telemetry Stream
            </span>
          </div>
          <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">
            Security Operations Center & Multi-Agent Correlation
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Autonomous ingestion of Network, Host/System, and Web Application event streams with real-time heuristic correlation, ML classification, and risk triage.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs">
          <button
            id="btn-dash-log-explorer"
            onClick={() => onNavigate('log-explorer')}
            className="px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold transition-colors shadow-lg shadow-cyan-600/20"
          >
            Upload New Log Stream
          </button>
          <button
            id="btn-dash-incidents"
            onClick={() => onNavigate('incidents')}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors border border-slate-700"
          >
            View Active Incidents ({metrics.criticalIncidents})
          </button>
        </div>
      </div>

      {/* 4. DASHBOARD FOUNDATION - SUMMARY CARDS */}
      <section aria-label="Summary Metrics">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-cyan-400" />
            SOC Telemetry Summary
          </h3>
          <span className="text-[11px] font-mono text-slate-500">
            Updated: {new Date(metrics.lastUpdated).toLocaleTimeString()}
          </span>
        </div>

        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 gap-3">
          <StatCard
            id="card-total-events"
            title="Total Events"
            value={metrics.totalEvents}
            subtitle="All channels"
            change="+8.4% /hr"
            icon={Activity}
            variant="default"
          />
          <StatCard
            id="card-suspicious-events"
            title="Suspicious Events"
            value={metrics.suspiciousEvents}
            subtitle="Flagged by heuristic"
            change="+14.2%"
            isIncreaseNegative
            icon={AlertTriangle}
            variant="warning"
          />
          <StatCard
            id="card-active-threats"
            title="Active Threats"
            value={metrics.activeThreats}
            subtitle="Under investigation"
            change="+3 new"
            isIncreaseNegative
            icon={ShieldAlert}
            variant="critical"
          />
          <StatCard
            id="card-critical-incidents"
            title="Critical Incidents"
            value={metrics.criticalIncidents}
            subtitle="Action required"
            change="P0 severity"
            isIncreaseNegative
            icon={Flame}
            variant="critical"
          />
          <StatCard
            id="card-network-events"
            title="Network Events"
            value={metrics.networkEvents}
            subtitle="Suricata / Bro"
            icon={Network}
            variant="info"
          />
          <StatCard
            id="card-system-events"
            title="System Events"
            value={metrics.systemEvents}
            subtitle="Wazuh / Sysmon"
            icon={Server}
            variant="emerald"
          />
          <StatCard
            id="card-application-events"
            title="Application Events"
            value={metrics.applicationEvents}
            subtitle="Nginx / APIs"
            icon={Globe}
            variant="default"
          />
        </div>
      </section>

      {/* 6. AGENT STATUS SECTION */}
      <section aria-label="Agent Status" id="section-agent-status">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2 font-mono">
              <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
              SPECIALIZED MULTI-AGENT STATUS
            </h3>
            <p className="text-xs text-slate-400">
              Autonomous agents evaluating domain-specific logs before dispatching to the Event Correlation Engine.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {agents.map(agent => (
            <AgentStatusCard
              key={agent.agentId}
              agent={agent}
              onToggleStatus={onToggleAgentStatus}
              onViewDetails={agentId => {
                if (agentId === 'NETWORK_AGENT') onNavigate('network-agent');
                else if (agentId === 'SYSTEM_AGENT') onNavigate('system-agent');
                else if (agentId === 'APPLICATION_AGENT') onNavigate('application-agent');
              }}
            />
          ))}
        </div>
      </section>

      {/* 5. DASHBOARD VISUALIZATIONS */}
      <section aria-label="Visualizations" className="space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
            Threat Analytics & Visualizations
          </h3>
          <span className="text-[11px] font-mono text-slate-500">
            Timeframe: Past 6 Hours
          </span>
        </div>

        {/* Top Charts Row: Events Over Time & Severity Distribution */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 p-4 rounded-xl bg-slate-900/70 border border-slate-800">
            <div className="flex items-center justify-between mb-2">
              <div>
                <h4 className="text-sm font-bold text-white font-mono">
                  1. Events Over Time
                </h4>
                <p className="text-[11px] text-slate-400">
                  Rate of ingested log events across Network, System, and Application feeds.
                </p>
              </div>
            </div>
            <EventsOverTimeChart data={eventsOverTime} height={260} />
          </div>

          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
            <div className="mb-2">
              <h4 className="text-sm font-bold text-white font-mono">
                2. Threat Severity Distribution
              </h4>
              <p className="text-[11px] text-slate-400">
                Categorization of flagged events by severity level.
              </p>
            </div>
            <ThreatSeverityChart data={severityDistribution} height={260} />
          </div>
        </div>

        {/* Second Charts Row: Events by Source, Agent Activity, Threat Categories */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
            <div className="mb-2">
              <h4 className="text-sm font-bold text-white font-mono">
                3. Events by Source
              </h4>
              <p className="text-[11px] text-slate-400">
                Log volume vs identified threat ratio per source.
              </p>
            </div>
            <EventsBySourceChart data={eventsBySource} height={240} />
          </div>

          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
            <div className="mb-2">
              <h4 className="text-sm font-bold text-white font-mono">
                4. Agent Activity
              </h4>
              <p className="text-[11px] text-slate-400">
                Processing rate (events/sec) per specialized agent.
              </p>
            </div>
            <AgentActivityChart data={agentActivity} height={240} />
          </div>

          <div className="p-4 rounded-xl bg-slate-900/70 border border-slate-800">
            <div className="mb-2">
              <h4 className="text-sm font-bold text-white font-mono">
                5. Threat Categories
              </h4>
              <p className="text-[11px] text-slate-400">
                Top MITRE ATT&CK tactic classification counts.
              </p>
            </div>
            <ThreatCategoriesChart data={threatCategories} height={240} />
          </div>
        </div>
      </section>

      {/* 7. RECENT SECURITY EVENTS TABLE */}
      <section aria-label="Recent Security Events" id="section-recent-events">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2 font-mono">
              6. RECENT SECURITY EVENTS
            </h3>
            <p className="text-xs text-slate-400">
              Live chronological telemetry with severity, calculated risk score, and automated containment proposals.
            </p>
          </div>
          <button
            onClick={() => onNavigate('threat-detection')}
            className="text-xs font-mono text-cyan-400 hover:text-cyan-300 underline underline-offset-4"
          >
            Explore All Detections →
          </button>
        </div>

        <RecentEventsTable events={recentEvents} />
      </section>
    </div>
  );
};
