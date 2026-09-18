import React, { useState, useEffect } from 'react';
import {
  Network,
  Server,
  Globe,
  GitMerge,
  ShieldAlert,
  Bell,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Power,
  Activity,
  Sliders,
  ExternalLink,
  ShieldCheck,
  Cpu
} from 'lucide-react';
import { NavPageId } from '../../../types';
import { networkAgentService } from '../../../services/networkAgentService';
import { systemAgentService } from '../../../services/systemAgentService';
import { applicationAgentService } from '../../../services/applicationAgentService';
import { correlationService } from '../../../services/correlationService';
import { threatDetectionService } from '../../../services/threatDetectionService';
import { alertManager } from '../../../services/alertIncident/alertManager';
import { incidentManager } from '../../../services/alertIncident/incidentManager';
import { logRepository } from '../../../services/logRepository';

interface AgentDetailCard {
  id: string;
  name: string;
  role: string;
  status: 'AVAILABLE' | 'PROCESSING' | 'IDLE' | 'ERROR' | 'OFFLINE' | 'NOT_CONFIGURED' | 'ACTIVE' | 'STANDBY';
  hasProcessedRealEvent?: boolean;
  realEventsProcessed?: number;
  simulatedEventsProcessed?: number;
  eventsProcessed: number;
  threatsDetected?: number;
  lastProcessedEvent: string;
  lastProcessedTimestamp: string;
  errorCount: number;
  lastError?: string | null;
  icon: React.ComponentType<{ className?: string }>;
  accentColor: string;
  badgeBg: string;
  badgeBorder: string;
  pageId?: NavPageId;
  capabilities: string[];
}

interface MultiAgentStatusSectionProps {
  onNavigate?: (page: NavPageId) => void;
}

export const MultiAgentStatusSection: React.FC<MultiAgentStatusSectionProps> = ({
  onNavigate
}) => {
  const [agents, setAgents] = useState<AgentDetailCard[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [lastSynced, setLastSynced] = useState<string>(new Date().toLocaleTimeString());

  const fetchAgentStatuses = async () => {
    setIsLoading(true);
    try {
      let backendAgents: any[] = [];
      try {
        const resp = await fetch('/api/pipeline/status');
        if (resp.ok) {
          const data = await resp.json();
          if (Array.isArray(data.agents)) {
            backendAgents = data.agents;
          }
        }
      } catch {
        // Fallback if backend offline
      }

      const agentMeta: Record<string, {
        id: string;
        icon: React.ComponentType<{ className?: string }>;
        accentColor: string;
        badgeBg: string;
        badgeBorder: string;
        pageId?: NavPageId;
      }> = {
        SYSTEM_AGENT: {
          id: 'system-agent',
          icon: Server,
          accentColor: 'text-purple-400',
          badgeBg: 'bg-purple-950/20',
          badgeBorder: 'border-purple-500/30',
          pageId: 'system-agent'
        },
        APPLICATION_AGENT: {
          id: 'application-agent',
          icon: Globe,
          accentColor: 'text-emerald-400',
          badgeBg: 'bg-emerald-950/20',
          badgeBorder: 'border-emerald-500/30',
          pageId: 'application-agent'
        },
        NETWORK_AGENT: {
          id: 'network-agent',
          icon: Network,
          accentColor: 'text-cyan-400',
          badgeBg: 'bg-cyan-950/20',
          badgeBorder: 'border-cyan-500/30',
          pageId: 'network-agent'
        },
        CORRELATION_AGENT: {
          id: 'event-correlation-agent',
          icon: GitMerge,
          accentColor: 'text-indigo-400',
          badgeBg: 'bg-indigo-950/20',
          badgeBorder: 'border-indigo-500/30',
          pageId: 'event-correlation'
        },
        THREAT_DETECTION_AGENT: {
          id: 'threat-detection-agent',
          icon: ShieldAlert,
          accentColor: 'text-rose-400',
          badgeBg: 'bg-rose-950/20',
          badgeBorder: 'border-rose-500/30',
          pageId: 'threat-detection'
        },
        ALERT_RESPONSE_AGENT: {
          id: 'alert-agent',
          icon: Bell,
          accentColor: 'text-amber-400',
          badgeBg: 'bg-amber-950/20',
          badgeBorder: 'border-amber-500/30',
          pageId: 'alerts'
        }
      };

      if (backendAgents.length > 0) {
        const mappedList: AgentDetailCard[] = backendAgents.map((agent: any) => {
          const meta = agentMeta[agent.agentId] || {
            id: agent.agentId.toLowerCase().replace(/_/g, '-'),
            icon: Cpu,
            accentColor: 'text-slate-400',
            badgeBg: 'bg-slate-900',
            badgeBorder: 'border-slate-800',
            pageId: undefined as NavPageId | undefined
          };

          return {
            id: meta.id,
            name: agent.name,
            role: agent.role,
            status: agent.status,
            hasProcessedRealEvent: agent.hasProcessedRealEvent,
            realEventsProcessed: agent.realEventsProcessed || 0,
            simulatedEventsProcessed: agent.simulatedEventsProcessed || 0,
            eventsProcessed: agent.totalEventsProcessed || 0,
            threatsDetected: agent.threatsDetected || 0,
            errorCount: agent.errorCount || 0,
            lastError: agent.lastError,
            lastProcessedEvent: agent.lastProcessedEventId
              ? `Processed Event ID: ${agent.lastProcessedEventId}`
              : (agent.hasProcessedRealEvent ? 'Live telemetry event processed' : 'Awaiting incoming telemetry...'),
            lastProcessedTimestamp: agent.lastActivity
              ? new Date(agent.lastActivity).toLocaleTimeString()
              : 'Idle / Ready',
            icon: meta.icon,
            accentColor: meta.accentColor,
            badgeBg: meta.badgeBg,
            badgeBorder: meta.badgeBorder,
            pageId: meta.pageId,
            capabilities: agent.capabilities || []
          };
        });

        setAgents(mappedList);
      } else {
        // Default clean state when no events processed yet: status AVAILABLE, counts 0
        const defaultList: AgentDetailCard[] = [
          {
            id: 'network-agent',
            name: 'Network Monitoring Agent',
            role: 'Network Flow & Socket Connection Inspection',
            status: 'AVAILABLE',
            lastProcessedEvent: 'Awaiting incoming telemetry...',
            lastProcessedTimestamp: 'Idle / Ready',
            eventsProcessed: 0,
            errorCount: 0,
            icon: Network,
            accentColor: 'text-cyan-400',
            badgeBg: 'bg-cyan-950/20',
            badgeBorder: 'border-cyan-500/30',
            pageId: 'network-agent',
            capabilities: [
              'Active socket table connection monitoring',
              'SYN flood & UDP volumetric attack detection',
              'Port sweep and reconnaissance detection',
              'Suspicious external IP beaconing tracking'
            ]
          },
          {
            id: 'system-agent',
            name: 'System Monitoring Agent',
            role: 'Windows Event Logs, Security Audit & Host Surveillance',
            status: 'AVAILABLE',
            lastProcessedEvent: 'Awaiting incoming telemetry...',
            lastProcessedTimestamp: 'Idle / Ready',
            eventsProcessed: 0,
            errorCount: 0,
            icon: Server,
            accentColor: 'text-purple-400',
            badgeBg: 'bg-purple-950/20',
            badgeBorder: 'border-purple-500/30',
            pageId: 'system-agent',
            capabilities: [
              'Windows Event Log 4625 failed logon surveillance',
              'Process creation 4688 tracking & command-line audit',
              'LSASS credential dumping (Mimikatz) detection',
              'Privilege escalation & token manipulation detection'
            ]
          },
          {
            id: 'application-agent',
            name: 'Application Monitoring Agent',
            role: 'Web Application & Service Log Gateway',
            status: 'AVAILABLE',
            lastProcessedEvent: 'Awaiting incoming telemetry...',
            lastProcessedTimestamp: 'Idle / Ready',
            eventsProcessed: 0,
            errorCount: 0,
            icon: Globe,
            accentColor: 'text-emerald-400',
            badgeBg: 'bg-emerald-950/20',
            badgeBorder: 'border-emerald-500/30',
            pageId: 'application-agent',
            capabilities: [
              'SQL injection syntax parsing & pattern matching',
              'Cross-Site Scripting (XSS) payload interception',
              'Directory traversal & path escape detection',
              'HTTP 4xx/5xx burst anomaly scoring'
            ]
          },
          {
            id: 'event-correlation-agent',
            name: 'Event Correlation Agent',
            role: 'Temporal Sliding-Window Cross-Agent Graph Engine',
            status: 'AVAILABLE',
            lastProcessedEvent: 'Awaiting incoming telemetry...',
            lastProcessedTimestamp: 'Idle / Ready',
            eventsProcessed: 0,
            errorCount: 0,
            icon: GitMerge,
            accentColor: 'text-indigo-400',
            badgeBg: 'bg-indigo-950/20',
            badgeBorder: 'border-indigo-500/30',
            pageId: 'event-correlation',
            capabilities: [
              'Multi-source sliding window aggregation (300s)',
              'Entity pivot cross-matching (IP, Host, User)',
              'MITRE ATT&CK kill-chain progression discovery',
              'Confidence-weighted correlation scoring'
            ]
          },
          {
            id: 'threat-detection-agent',
            name: 'Threat Detection Agent',
            role: 'Hybrid Random Forest & Isolation Forest ML Engine',
            status: 'AVAILABLE',
            lastProcessedEvent: 'Awaiting incoming telemetry...',
            lastProcessedTimestamp: 'Idle / Ready',
            eventsProcessed: 0,
            errorCount: 0,
            icon: ShieldAlert,
            accentColor: 'text-rose-400',
            badgeBg: 'bg-rose-950/20',
            badgeBorder: 'border-rose-500/30',
            pageId: 'threat-detection',
            capabilities: [
              'Supervised Random Forest threat classification',
              'Unsupervised Isolation Forest anomaly scoring',
              'Feature importance & explainability factors',
              'Dual-layer heuristic and ML consensus evaluation'
            ]
          },
          {
            id: 'alert-agent',
            name: 'Alert and Response Agent',
            role: '7-Factor Risk Scoring, Alert Generation & Incident Escalation',
            status: 'AVAILABLE',
            lastProcessedEvent: 'Awaiting incoming telemetry...',
            lastProcessedTimestamp: 'Idle / Ready',
            eventsProcessed: 0,
            errorCount: 0,
            icon: Bell,
            accentColor: 'text-amber-400',
            badgeBg: 'bg-amber-950/20',
            badgeBorder: 'border-amber-500/30',
            pageId: 'alerts',
            capabilities: [
              'Mathematical 7-factor evidence-based risk scoring (0-100)',
              'Heuristic alert deduplication and suppression',
              'Automated incident ticket creation with containment actions',
              'Full SOC audit logging and traceability tracking'
            ]
          }
        ];
        setAgents(defaultList);
      }
      setLastSynced(new Date().toLocaleTimeString());
    } catch (err) {
      console.error('Failed to sync agent statuses:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchAgentStatuses();
    const unsubLogs = logRepository.subscribe(fetchAgentStatuses);
    const unsubAlerts = alertManager.subscribe(fetchAgentStatuses);
    const unsubIncidents = incidentManager.subscribe(fetchAgentStatuses);
    return () => {
      unsubLogs();
      unsubAlerts();
      unsubIncidents();
    };
  }, []);

  const handleToggleAgent = (agentId: string) => {
    setAgents(prev =>
      prev.map(a => {
        if (a.id === agentId) {
          const nextStatus = a.status === 'ACTIVE' ? 'STANDBY' : 'ACTIVE';
          return { ...a, status: nextStatus };
        }
        return a;
      })
    );
  };

  return (
    <div className="space-y-6 font-mono" id="dashboard-section-multi-agent">
      {/* Header & Controls */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 shadow-xl">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" />
              Multi-Agent Fleet Surveillance Status
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-700">
              6 of 6 Synchronized
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time operating status, throughput volumes, latest event telemetry, and error logging across all 6 specialized agents.
          </p>
        </div>

        <div className="flex items-center gap-2 text-xs">
          <span className="text-slate-500">Synced: {lastSynced}</span>
          <button
            onClick={fetchAgentStatuses}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            <span>Probe Fleet</span>
          </button>
        </div>
      </div>

      {/* 6 Specialized Agents Bento Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {agents.map(agent => {
          const Icon = agent.icon;
          const statusConfig = (() => {
            switch (agent.status) {
              case 'ACTIVE':
                return {
                  label: 'ACTIVE',
                  classes: 'bg-emerald-950/90 text-emerald-300 border-emerald-700',
                  dot: 'bg-emerald-400 animate-pulse'
                };
              case 'PROCESSING':
                return {
                  label: 'PROCESSING',
                  classes: 'bg-cyan-950/90 text-cyan-300 border-cyan-700',
                  dot: 'bg-cyan-400 animate-ping'
                };
              case 'AVAILABLE':
                return {
                  label: 'AVAILABLE',
                  classes: 'bg-sky-950/90 text-sky-300 border-sky-700',
                  dot: 'bg-sky-400'
                };
              case 'IDLE':
                return {
                  label: 'IDLE',
                  classes: 'bg-slate-800 text-slate-300 border-slate-700',
                  dot: 'bg-slate-400'
                };
              case 'ERROR':
                return {
                  label: 'ERROR',
                  classes: 'bg-rose-950/90 text-rose-300 border-rose-700',
                  dot: 'bg-rose-500 animate-pulse'
                };
              case 'OFFLINE':
                return {
                  label: 'OFFLINE',
                  classes: 'bg-zinc-900 text-zinc-400 border-zinc-700',
                  dot: 'bg-zinc-500'
                };
              case 'NOT_CONFIGURED':
                return {
                  label: 'NOT CONFIGURED',
                  classes: 'bg-amber-950/90 text-amber-300 border-amber-700',
                  dot: 'bg-amber-500'
                };
              default:
                return {
                  label: agent.status,
                  classes: 'bg-slate-800 text-slate-300 border-slate-700',
                  dot: 'bg-slate-400'
                };
            }
          })();

          return (
            <div
              key={agent.id}
              className={`p-5 rounded-xl border ${agent.badgeBorder} ${agent.badgeBg} bg-slate-900 shadow-xl flex flex-col justify-between space-y-4`}
            >
              {/* Card Header: Icon, Name, and Status */}
              <div>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2.5">
                    <div className={`p-2 rounded-lg bg-slate-950 border border-slate-800 ${agent.accentColor}`}>
                      <Icon className="w-5 h-5" />
                    </div>
                    <div>
                      <h4 className="text-sm font-bold text-white tracking-tight">{agent.name}</h4>
                      <p className="text-[10px] text-slate-400">{agent.role}</p>
                    </div>
                  </div>

                  {/* Status Badge */}
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border flex items-center gap-1.5 ${statusConfig.classes}`}
                    >
                      <span className={`w-1.5 h-1.5 rounded-full ${statusConfig.dot}`} />
                      {statusConfig.label}
                    </span>
                  </div>
                </div>

                {/* Key Telemetry Metrics */}
                <div className="grid grid-cols-2 gap-2 mt-4 pt-3 border-t border-slate-800/80">
                  <div className="p-2 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Events Processed</span>
                    <span className="text-sm font-bold text-white font-mono">
                      {agent.eventsProcessed.toLocaleString()}
                    </span>
                    <div className="text-[9px] text-slate-500 mt-0.5">
                      {agent.realEventsProcessed ?? 0} Real · {agent.simulatedEventsProcessed ?? 0} Sim
                    </div>
                  </div>

                  <div className="p-2 rounded bg-slate-950 border border-slate-800">
                    <span className="text-[10px] text-slate-500 uppercase block">Threats & Errors</span>
                    <span className={`text-sm font-bold font-mono ${(agent.threatsDetected ?? 0) > 0 ? 'text-amber-400' : 'text-slate-300'}`}>
                      {agent.threatsDetected ?? 0} Threats
                    </span>
                    <div className={`text-[9px] mt-0.5 font-medium ${agent.errorCount === 0 ? 'text-emerald-400' : 'text-rose-400'}`}>
                      {agent.errorCount === 0 ? '0 Errors / Healthy' : `${agent.errorCount} Errors`}
                    </div>
                  </div>
                </div>

                {/* Last Error Banner if present */}
                {agent.lastError && (
                  <div className="mt-2 p-2 rounded bg-rose-950/40 border border-rose-800 text-[10px] text-rose-300">
                    <span className="font-semibold block">Last Error:</span>
                    <span className="line-clamp-1">{agent.lastError}</span>
                  </div>
                )}

                {/* Last Processed Event */}
                <div className="mt-3 p-2.5 rounded bg-slate-950 border border-slate-800/90">
                  <div className="flex items-center justify-between text-[10px] text-slate-400 mb-1">
                    <span className="uppercase font-semibold">Last Processed Event</span>
                    <span className="text-slate-500">{agent.lastProcessedTimestamp}</span>
                  </div>
                  <p className="text-xs text-slate-300 line-clamp-2 leading-relaxed">
                    {agent.lastProcessedEvent}
                  </p>
                </div>

                {/* Capabilities Chips */}
                <div className="mt-3">
                  <span className="text-[10px] text-slate-500 uppercase block mb-1.5 font-semibold">
                    Core Detection Capabilities
                  </span>
                  <div className="space-y-1">
                    {agent.capabilities.map((cap, i) => (
                      <div key={i} className="text-[11px] text-slate-400 flex items-center gap-1.5">
                        <CheckCircle2 className="w-2.5 h-2.5 text-cyan-400 flex-shrink-0" />
                        <span className="truncate">{cap}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Console Link */}
              {agent.pageId && onNavigate && (
                <button
                  onClick={() => onNavigate(agent.pageId!)}
                  className="w-full py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors flex items-center justify-center gap-1.5 border border-slate-700"
                >
                  <span>Open {agent.name} Console</span>
                  <ExternalLink className="w-3 h-3 text-cyan-400" />
                </button>
              )}
            </div>
          );
        })}
      </div>

      {/* Fleet Synchronization & Message Bus Topology */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-2">
        <h4 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          Autonomous Multi-Agent Collaboration Protocol
        </h4>
        <p className="text-xs text-slate-400 leading-relaxed">
          The 6 agents operate asynchronously over an in-memory Pub/Sub event bus. Specialized perimeter agents (Network, System, Application) parse and normalize raw protocol events, extracting statistical and behavioral vectors. The Correlation Agent aggregates these via sliding temporal windows, feeding correlated multi-source graphs into the Threat Detection Agent (Random Forest classification & Isolation Forest anomaly scoring). Flagged attacks are routed to the Alert Agent for deduplication and incident lifecycle tracking.
        </p>
      </div>
    </div>
  );
};
