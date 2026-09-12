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
  Radio,
  Cpu
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
          <button
            id="btn-dash-correlation"
            onClick={() => onNavigate('correlation')}
            className="px-3 py-2 rounded-lg bg-indigo-950 hover:bg-indigo-900 text-indigo-200 transition-colors border border-indigo-700 flex items-center gap-1.5"
          >
            <Radio className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
            <span>Event Correlation</span>
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

      {/* MULTI-AGENT CORRELATION & THREAT DETECTION ENGINES */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Correlation Engine Card */}
        <section aria-label="Event Correlation Quick Access" className="p-4 bg-gradient-to-r from-slate-900 via-indigo-950/40 to-slate-900 border border-indigo-500/30 rounded-xl flex flex-col justify-between gap-3 shadow-md">
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400 shrink-0">
              <Radio className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400">
                  Event Correlation Engine
                </span>
                <span className="px-2 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px] font-mono">
                  ACTIVE
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">
                Synthesizing temporal, IP, host, and multi-stage sequences across Network, System, and Application agents.
              </p>
            </div>
          </div>

          <div className="flex justify-end pt-2 border-t border-slate-800/80">
            <button
              id="btn-dash-open-correlation"
              onClick={() => onNavigate('correlation')}
              className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold flex items-center gap-1.5 transition-colors shadow-sm"
            >
              <span>Correlation Engine →</span>
            </button>
          </div>
        </section>

        {/* AI/ML Threat Detection Card */}
        <section aria-label="AI/ML Threat Detection Quick Access" className="p-4 bg-gradient-to-r from-slate-900 via-purple-950/40 to-slate-900 border border-purple-500/30 rounded-xl flex flex-col justify-between gap-3 shadow-md">
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-lg bg-purple-950 border border-purple-800 text-purple-400 shrink-0">
              <Cpu className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold uppercase tracking-wider text-purple-300">
                  AI/ML Threat Detection Layer
                </span>
                <span className="px-2 py-0.2 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 text-[10px] font-mono">
                  DEMO / NOT TRAINED
                </span>
              </div>
              <p className="text-xs text-slate-300 mt-1">
                18-feature extraction, Min-Max normalization, candidate Random Forest & Isolation Forest with Explainable AI attribution.
              </p>
            </div>
          </div>

          <div className="flex justify-end pt-2 border-t border-slate-800/80">
            <button
              id="btn-dash-open-threat-detection"
              onClick={() => onNavigate('threat-detection')}
              className="px-3 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-xs font-mono font-bold flex items-center gap-1.5 transition-colors shadow-sm"
            >
              <span>Threat Detection Layer →</span>
            </button>
          </div>
        </section>
      </div>

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
