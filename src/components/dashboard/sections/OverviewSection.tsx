import React from 'react';
import {
  ShieldAlert,
  Flame,
  AlertTriangle,
  Bell,
  Activity,
  CheckCircle2,
  Database,
  ArrowRight,
  Info,
  Layers,
  Cpu,
  Radio,
  Server,
  Network,
  Globe,
  GitMerge,
  Terminal,
  ShieldCheck,
  TrendingUp,
  FileSpreadsheet
} from 'lucide-react';
import { SecurityOverviewData } from '../../../services/unifiedAnalyticsService';
import { DashboardMetrics, NavPageId } from '../../../types';

export type DashboardSectionTab =
  | 'OVERVIEW'
  | 'LIVE_EVENTS'
  | 'MULTI_AGENT'
  | 'THREAT_DETECTION'
  | 'INCIDENTS'
  | 'ANALYTICS'
  | 'REPORTS';

interface OverviewSectionProps {
  overview?: SecurityOverviewData | null;
  metrics?: DashboardMetrics | null;
  isRealData: boolean;
  onNavigate?: (page: NavPageId) => void;
  onSelectSection: (section: DashboardSectionTab) => void;
}

export const OverviewSection: React.FC<OverviewSectionProps> = ({
  overview,
  metrics,
  isRealData,
  onNavigate,
  onSelectSection
}) => {
  const totalEvents = metrics?.totalEvents ?? overview?.totalEvents ?? 0;
  const openIncidents = overview?.openIncidents ?? 0;
  const resolvedIncidents = overview?.resolvedIncidents ?? 0;
  const totalIncidents = openIncidents + resolvedIncidents;
  const criticalAlerts = overview?.criticalThreats ?? 0;
  const highAlerts = overview?.highThreats ?? 0;

  // Derive honest system status
  const getSystemStatus = () => {
    if (criticalAlerts > 0) {
      return {
        label: 'ACTIVE THREAT DETECTED',
        badge: 'bg-rose-950/80 text-rose-300 border-rose-800',
        dot: 'bg-rose-500',
        cardBorder: 'border-rose-900/60 bg-rose-950/10',
        description: `${criticalAlerts} critical alert(s) requiring active investigation and containment.`
      };
    }
    if (highAlerts > 0) {
      return {
        label: 'ELEVATED MONITORING',
        badge: 'bg-amber-950/80 text-amber-300 border-amber-800',
        dot: 'bg-amber-500',
        cardBorder: 'border-amber-900/60 bg-amber-950/10',
        description: `${highAlerts} high-severity threat(s) flagged by ML and signature heuristics.`
      };
    }
    return {
      label: 'ALL AGENTS OPERATIONAL',
      badge: 'bg-emerald-950/80 text-emerald-300 border-emerald-800',
      dot: 'bg-emerald-500',
      cardBorder: 'border-emerald-900/60 bg-emerald-950/10',
      description: 'Zero unresolved critical anomalies. Cooperative agent telemetry stream healthy.'
    };
  };

  const status = getSystemStatus();

  return (
    <div className="space-y-6 font-mono" id="dashboard-section-overview">
      {/* 1. Academic Presentation & Data Provenance Disclosure Banner */}
      <div className={`p-4 sm:p-5 rounded-xl border ${status.cardBorder} flex flex-col md:flex-row items-start md:items-center justify-between gap-4 shadow-xl`}>
        <div className="flex items-start sm:items-center gap-3">
          <div className="relative mt-1 sm:mt-0 flex-shrink-0">
            <span className={`w-3.5 h-3.5 rounded-full ${status.dot} animate-ping absolute inset-0 opacity-75`} />
            <span className={`w-3.5 h-3.5 rounded-full ${status.dot} relative inline-block`} />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs text-slate-400 font-semibold uppercase tracking-wider">
                Current System Status:
              </span>
              <span className={`px-2.5 py-0.5 rounded text-xs font-bold border ${status.badge}`}>
                {status.label}
              </span>

              {/* Truthful Data Source Badging */}
              {isRealData ? (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-950/90 text-emerald-300 border border-emerald-700">
                  INGESTED LOG / REAL BENCHMARK
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-indigo-950/90 text-indigo-300 border border-indigo-700">
                  DETERMINISTIC SIMULATOR / EVALUATION SCENARIO
                </span>
              )}
            </div>
            <p className="text-xs text-slate-300 mt-1">
              {status.description}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2 self-end md:self-center text-xs text-slate-400">
          <span>Updated:</span>
          <span className="text-slate-200 font-semibold">{overview?.lastUpdated || 'Live Sync'}</span>
        </div>
      </div>

      {/* 2. Top-Level Core Metrics Cards (Required 6 Items) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Metric 1: Total Events */}
        <div
          id="stat-card-total-events"
          onClick={() => onSelectSection('LIVE_EVENTS')}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/60 transition-all cursor-pointer group shadow-lg"
        >
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase">
            <span>Total Events</span>
            <Database className="w-4 h-4 text-cyan-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-2xl font-bold text-white tracking-tight">
            {totalEvents.toLocaleString()}
          </div>
          <div className="mt-1 text-[10px] text-slate-500 flex items-center justify-between">
            <span>Telemetries Ingested</span>
            <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity text-cyan-400" />
          </div>
        </div>

        {/* Metric 2: Total Incidents */}
        <div
          id="stat-card-total-incidents"
          onClick={() => onSelectSection('INCIDENTS')}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-purple-500/60 transition-all cursor-pointer group shadow-lg"
        >
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase">
            <span>Total Incidents</span>
            <Layers className="w-4 h-4 text-purple-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-2xl font-bold text-purple-300 tracking-tight">
            {totalIncidents}
          </div>
          <div className="mt-1 text-[10px] text-slate-500 flex items-center justify-between">
            <span>{openIncidents} Open · {resolvedIncidents} Resolved</span>
            <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity text-purple-400" />
          </div>
        </div>

        {/* Metric 3: Critical Alerts */}
        <div
          id="stat-card-critical-alerts"
          onClick={() => onSelectSection('THREAT_DETECTION')}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-rose-500/60 transition-all cursor-pointer group shadow-lg"
        >
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase">
            <span>Critical Alerts</span>
            <Flame className="w-4 h-4 text-rose-500 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-2xl font-bold text-rose-400 tracking-tight">
            {criticalAlerts}
          </div>
          <div className="mt-1 text-[10px] text-rose-500/80 font-semibold flex items-center justify-between">
            <span>Immediate Triage</span>
            <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity text-rose-400" />
          </div>
        </div>

        {/* Metric 4: High-Severity Alerts */}
        <div
          id="stat-card-high-alerts"
          onClick={() => onSelectSection('THREAT_DETECTION')}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-amber-500/60 transition-all cursor-pointer group shadow-lg"
        >
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase">
            <span>High Alerts</span>
            <AlertTriangle className="w-4 h-4 text-amber-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-2xl font-bold text-amber-400 tracking-tight">
            {highAlerts}
          </div>
          <div className="mt-1 text-[10px] text-amber-500/80 font-semibold flex items-center justify-between">
            <span>Elevated Risk</span>
            <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity text-amber-400" />
          </div>
        </div>

        {/* Metric 5: Resolved Incidents */}
        <div
          id="stat-card-resolved-incidents"
          onClick={() => onSelectSection('INCIDENTS')}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-emerald-500/60 transition-all cursor-pointer group shadow-lg"
        >
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase">
            <span>Resolved</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-2xl font-bold text-emerald-400 tracking-tight">
            {resolvedIncidents}
          </div>
          <div className="mt-1 text-[10px] text-slate-500 flex items-center justify-between">
            <span>Remediated</span>
            <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity text-emerald-400" />
          </div>
        </div>

        {/* Metric 6: Current System Status */}
        <div
          id="stat-card-system-health"
          onClick={() => onSelectSection('MULTI_AGENT')}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/60 transition-all cursor-pointer group shadow-lg"
        >
          <div className="flex items-center justify-between text-slate-400 text-[11px] uppercase">
            <span>System State</span>
            <Activity className="w-4 h-4 text-emerald-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-lg font-bold text-slate-200 tracking-tight flex items-center gap-1.5 truncate">
            <span className={`w-2.5 h-2.5 rounded-full ${status.dot} flex-shrink-0`} />
            <span className="truncate">{status.label === 'ALL AGENTS OPERATIONAL' ? 'Nominal' : 'Guarded'}</span>
          </div>
          <div className="mt-1 text-[10px] text-slate-500 flex items-center justify-between">
            <span>6 Agents Ready</span>
            <ArrowRight className="w-3 h-3 opacity-0 group-hover:opacity-100 transition-opacity text-emerald-400" />
          </div>
        </div>
      </div>

      {/* 3. Defensive Multi-Agent Cooperative Architecture Summary */}
      <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
          <div>
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-cyan-400" />
              Multi-Agent Cooperative Defensive Pipeline
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Defensive cybersecurity monitoring across specialized network, host, and application surveillance agents.
            </p>
          </div>
          <div className="flex items-center gap-2 text-[11px]">
            <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
              Zero Unauthorized Access
            </span>
            <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
              Explainable AI Rules + ML
            </span>
          </div>
        </div>

        {/* Interactive 6-Agent Pipeline Strip */}
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            {
              id: 'NETWORK_AGENT',
              name: 'Network Agent',
              role: 'Flow Telemetry & Port Scan Detection',
              icon: Network,
              color: 'text-cyan-400',
              bg: 'bg-cyan-500/10',
              border: 'border-cyan-500/20'
            },
            {
              id: 'SYSTEM_AGENT',
              name: 'System Agent',
              role: 'Host Auth Failures & Sudo Escalation',
              icon: Server,
              color: 'text-purple-400',
              bg: 'bg-purple-500/10',
              border: 'border-purple-500/20'
            },
            {
              id: 'APPLICATION_AGENT',
              name: 'Application Agent',
              role: 'SQLi, XSS & Web Exploit Pattern Matching',
              icon: Globe,
              color: 'text-emerald-400',
              bg: 'bg-emerald-500/10',
              border: 'border-emerald-500/20'
            },
            {
              id: 'CORRELATION_AGENT',
              name: 'Correlation Agent',
              role: 'Cross-Source Sliding Window Attack Graph',
              icon: GitMerge,
              color: 'text-indigo-400',
              bg: 'bg-indigo-500/10',
              border: 'border-indigo-500/20'
            },
            {
              id: 'THREAT_DETECTION',
              name: 'Threat Agent',
              role: 'Random Forest + Isolation Forest ML',
              icon: ShieldAlert,
              color: 'text-rose-400',
              bg: 'bg-rose-500/10',
              border: 'border-rose-500/20'
            },
            {
              id: 'ALERT_AGENT',
              name: 'Alert Agent',
              role: 'Incident Lifecycle & Triage Escalation',
              icon: Bell,
              color: 'text-amber-400',
              bg: 'bg-amber-500/10',
              border: 'border-amber-500/20'
            }
          ].map(agent => {
            const Icon = agent.icon;
            return (
              <div
                key={agent.id}
                onClick={() => onSelectSection('MULTI_AGENT')}
                className={`p-3 rounded-lg border ${agent.border} ${agent.bg} hover:border-slate-600 transition-all cursor-pointer group`}
              >
                <div className="flex items-center gap-2">
                  <Icon className={`w-4 h-4 ${agent.color}`} />
                  <span className="text-xs font-bold text-white truncate">{agent.name}</span>
                </div>
                <p className="text-[10px] text-slate-400 mt-1.5 leading-snug line-clamp-2">
                  {agent.role}
                </p>
                <div className="mt-2 text-[10px] text-slate-500 flex items-center justify-between">
                  <span className="text-emerald-400 flex items-center gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    Active
                  </span>
                  <ArrowRight className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity text-slate-300" />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* 4. Quick Navigation Modules (Sections 2 to 7) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        <div
          onClick={() => onSelectSection('LIVE_EVENTS')}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/50 transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5" />
              2. Live Security Events
            </span>
            <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 group-hover:translate-x-1 transition-all" />
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Chronological event timeline displaying agent origin, event type, severity, and detection method.
          </p>
        </div>

        <div
          onClick={() => onSelectSection('MULTI_AGENT')}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-purple-500/50 transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-purple-400 uppercase tracking-wider flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5" />
              3. Multi-Agent Status
            </span>
            <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-purple-400 group-hover:translate-x-1 transition-all" />
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Real-time status, processed event volumes, error telemetry, and controls for all 6 specialized agents.
          </p>
        </div>

        <div
          onClick={() => onSelectSection('THREAT_DETECTION')}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-rose-500/50 transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-rose-400 uppercase tracking-wider flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5" />
              4. Threat Detection & ML
            </span>
            <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-rose-400 group-hover:translate-x-1 transition-all" />
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Threat categories, anomaly scores, rule vs ML comparison, and live sample explainability workbench.
          </p>
        </div>

        <div
          onClick={() => onSelectSection('INCIDENTS')}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-amber-500/50 transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-amber-400 uppercase tracking-wider flex items-center gap-1.5">
              <Layers className="w-3.5 h-3.5" />
              5. Incident Management
            </span>
            <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-amber-400 group-hover:translate-x-1 transition-all" />
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Incident dossier tracking, lifecycle state changes (Open/Investigating/Resolved), and analyst notes.
          </p>
        </div>

        <div
          onClick={() => onSelectSection('ANALYTICS')}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-emerald-500/50 transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-1.5">
              <TrendingUp className="w-3.5 h-3.5" />
              6. SOC Analytics & Models
            </span>
            <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-emerald-400 group-hover:translate-x-1 transition-all" />
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Events over time, category distributions, agent activity metrics, and held-out ML evaluation matrices.
          </p>
        </div>

        <div
          onClick={() => onSelectSection('REPORTS')}
          className="p-4 rounded-xl bg-slate-900 border border-slate-800 hover:border-indigo-500/50 transition-all cursor-pointer group"
        >
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-indigo-400 uppercase tracking-wider flex items-center gap-1.5">
              <FileSpreadsheet className="w-3.5 h-3.5" />
              7. Reports & Data Export
            </span>
            <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-indigo-400 group-hover:translate-x-1 transition-all" />
          </div>
          <p className="text-xs text-slate-400 mt-2">
            Export incidents as CSV/JSON, generate formal executive security dossiers, and filter by time range.
          </p>
        </div>
      </div>
    </div>
  );
};
