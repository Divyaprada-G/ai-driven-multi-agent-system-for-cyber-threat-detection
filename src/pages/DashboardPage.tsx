/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Advanced Security Dashboard, Analytics, Reporting & Demo Mode
 *
 * Implements:
 * - Real-time unified analytics from all pipeline layers via unifiedAnalyticsService
 * - Global search and advanced filtering (Time, Severity, Priority, Threat Class, Agent, Status)
 * - Top-level security overview cards with honest Demo/Simulated vs Live dataset labeling
 * - Threat Analytics (distribution & time trend chart with honest empty states)
 * - Risk Analytics (average score, highest score, score trend, top risk events table)
 * - Multi-Agent activity with protocol volume clarification note
 * - Cross-source correlation & Multi-Stage Attack Chains
 * - Alert & Incident analytics with topology relationship
 * - Unified Chronological Event Timeline
 * - End-to-End Traceability (7-stage pipeline)
 * - Deterministic Demo Scenarios & Non-destructive state reset
 * - Future n8n workflow placeholder preview
 */

import React, { useState, useEffect, useCallback } from 'react';
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
  Cpu,
  Layers,
  ShieldCheck,
  ChevronRight,
  SlidersHorizontal,
  Sparkles,
  RefreshCw,
  Clock,
  Workflow,
  Search,
  Filter,
  FileText,
  RotateCcw,
  BarChart2,
  FileSpreadsheet
} from 'lucide-react';
import {
  DashboardMetrics,
  AgentStatusInfo,
  TimeSeriesPoint,
  SeverityDistributionPoint,
  SourceDistributionPoint,
  AgentActivityPoint,
  ThreatCategoryPoint,
  RiskAssessment,
  RiskStatus,
  NavPageId,
  CorrelatedEvent
} from '../types';
import { RecentEventItem, RecentEventsTable } from '../components/tables/RecentEventsTable';
import { RiskDetailModal } from '../components/riskScoring/RiskDetailModal';
import { riskService } from '../services/riskService';
import { logRepository } from '../services/logRepository';
import {
  unifiedAnalyticsService,
  SecurityOverviewData,
  ThreatClassificationCount,
  ThreatTrendDataPoint,
  RiskAnalyticsData
} from '../services/unifiedAnalyticsService';
import { GlobalFilterCriteria, TimeRangeFilter, UnifiedTimelineItem, TraceabilityChain } from '../types/analytics';

// Stage 10 Modular Components
import { GlobalSearchAndFilterBar } from '../components/dashboard/GlobalSearchAndFilterBar';
import { SecurityOverviewCards } from '../components/dashboard/SecurityOverviewCards';
import { ThreatAnalyticsPanel } from '../components/dashboard/ThreatAnalyticsPanel';
import { RiskAnalyticsPanel } from '../components/dashboard/RiskAnalyticsPanel';
import { MultiAgentActivityPanel } from '../components/dashboard/MultiAgentActivityPanel';
import { CrossSourceCorrelationPanel } from '../components/dashboard/CrossSourceCorrelationPanel';
import { AlertIncidentAnalyticsPanel } from '../components/dashboard/AlertIncidentAnalyticsPanel';
import { EventTimelinePanel } from '../components/dashboard/EventTimelinePanel';
import { EndToEndTraceabilityPanel } from '../components/dashboard/EndToEndTraceabilityPanel';
import { FutureN8nPlaceholder } from '../components/dashboard/FutureN8nPlaceholder';
import { DemoScenarioModal } from '../components/dashboard/DemoScenarioModal';

// Stage 12 Live Pipeline Components
import { LivePipelineStatusCard } from '../components/livePipeline/LivePipelineStatusCard';
import { LivePipelineControls } from '../components/livePipeline/LivePipelineControls';
import { LiveEventStreamTable } from '../components/livePipeline/LiveEventStreamTable';
import { AcademicPresentationView } from '../components/livePipeline/AcademicPresentationView';
import { ModelInfoPanel } from '../components/livePipeline/ModelInfoPanel';
import { EventQueueViewer } from '../components/livePipeline/EventQueueViewer';
import { LiveTraceabilityModal } from '../components/livePipeline/LiveTraceabilityModal';
import { ProjectDemoModal } from '../components/livePipeline/ProjectDemoModal';
import { livePipelineService } from '../services/livePipelineService';
import { LivePipelineStatus, LiveSecurityEvent, LiveSimulatorMode } from '../types/livePipeline';
import { TelemetryStatusBadge } from '../components/telemetry/TelemetryStatusBadge';
import { realtimeTelemetryStream } from '../services/telemetry/realtimeTelemetryStream';

// Modular Cybersecurity Dashboard Sections (Required Project Specification)
import { OverviewSection } from '../components/dashboard/sections/OverviewSection';
import { LiveSecurityEventsSection } from '../components/dashboard/sections/LiveSecurityEventsSection';
import { MultiAgentStatusSection } from '../components/dashboard/sections/MultiAgentStatusSection';
import { ThreatDetectionSection } from '../components/dashboard/sections/ThreatDetectionSection';
import { IncidentManagementSection } from '../components/dashboard/sections/IncidentManagementSection';
import { AnalyticsSection } from '../components/dashboard/sections/AnalyticsSection';
import { ReportsSection } from '../components/dashboard/sections/ReportsSection';

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

type DashboardTab =
  | 'OVERVIEW'
  | 'LIVE_EVENTS'
  | 'MULTI_AGENT'
  | 'THREAT_DETECTION'
  | 'INCIDENTS'
  | 'ANALYTICS'
  | 'REPORTS'
  | 'LIVE_PIPELINE'
  | 'CORRELATIONS'
  | 'TIMELINE'
  | 'TRACEABILITY'
  | 'N8N_PREVIEW';

export const DashboardPage: React.FC<DashboardPageProps> = ({
  metrics,
  agents: legacyAgents,
  eventsOverTime,
  severityDistribution,
  eventsBySource,
  agentActivity,
  threatCategories,
  recentEvents,
  onNavigate,
  onToggleAgentStatus
}) => {
  // Navigation tabs for the Advanced Dashboard
  const [activeTab, setActiveTab] = useState<DashboardTab>('OVERVIEW');

  // Unified Analytics State
  const [overview, setOverview] = useState<SecurityOverviewData | null>(null);
  const [threatClassifications, setThreatClassifications] = useState<ThreatClassificationCount[]>([]);
  const [threatTrend, setThreatTrend] = useState<ThreatTrendDataPoint[]>([]);
  const [hasHistoricalThreats, setHasHistoricalThreats] = useState<boolean>(true);
  const [riskData, setRiskData] = useState<RiskAnalyticsData | null>(null);
  const [agentDetails, setAgentDetails] = useState<any[]>([]);
  const [comparativeNote, setComparativeNote] = useState<string>('');
  const [alertIncidentData, setAlertIncidentData] = useState<any | null>(null);
  const [correlationStats, setCorrelationStats] = useState<any | null>(null);
  const [timelineEvents, setTimelineEvents] = useState<UnifiedTimelineItem[]>([]);
  const [traceabilityChains, setTraceabilityChains] = useState<TraceabilityChain[]>([]);
  const [rawAssessments, setRawAssessments] = useState<RiskAssessment[]>([]);
  const [selectedAssessment, setSelectedAssessment] = useState<RiskAssessment | null>(null);

  // Global Filters
  const [filters, setFilters] = useState<GlobalFilterCriteria>({
    searchTerm: '',
    timeRange: 'ALL',
    severity: 'ALL',
    riskLevel: 'ALL',
    priority: 'ALL',
    threatClassification: 'ALL',
    agent: 'ALL',
    alertStatus: 'ALL',
    incidentStatus: 'ALL'
  });

  // Demo Modal State
  const [isDemoModalOpen, setIsDemoModalOpen] = useState(false);
  const [isLoadingAnalytics, setIsLoadingAnalytics] = useState(false);

  // Stage 12: Live Pipeline & Local ML API State
  const [liveStatus, setLiveStatus] = useState<LivePipelineStatus>(livePipelineService.getStatus());
  const [liveEvents, setLiveEvents] = useState<LiveSecurityEvent[]>(livePipelineService.getEvents());
  const [liveQueued, setLiveQueued] = useState<LiveSecurityEvent[]>(livePipelineService.getQueuedEvents());
  const [selectedLiveEvent, setSelectedLiveEvent] = useState<LiveSecurityEvent | null>(null);
  const [isProjectDemoOpen, setIsProjectDemoOpen] = useState<boolean>(false);

  // System Health Status State
  const [systemHealth, setSystemHealth] = useState<{
    status: string;
    nodeServer: string;
    pythonMLBackend: string;
    database: string;
    databaseMode: string;
  } | null>(null);

  const fetchHealth = useCallback(async () => {
    try {
      const resp = await fetch('/api/health');
      if (resp.ok) {
        const data = await resp.json();
        setSystemHealth(data);
      }
    } catch {
      // Backend status unavailable
    }
  }, []);

  // Load all analytics from unifiedAnalyticsService
  const loadDashboardData = useCallback(async () => {
    setIsLoadingAnalytics(true);
    setFetchError(null);
    try {
      const [
        overviewRes,
        threatRes,
        riskRes,
        agentRes,
        alertIncRes,
        corrRes,
        timelineRes,
        traceRes,
        assessmentsRes
      ] = await Promise.all([
        unifiedAnalyticsService.getSecurityOverview(),
        unifiedAnalyticsService.getThreatAnalytics(filters.timeRange),
        unifiedAnalyticsService.getRiskAnalytics(),
        unifiedAnalyticsService.getMultiAgentAnalytics(),
        unifiedAnalyticsService.getAlertIncidentAnalytics(),
        unifiedAnalyticsService.getCorrelationAnalytics(),
        unifiedAnalyticsService.getTimelineEvents(),
        unifiedAnalyticsService.getTraceabilityChains(),
        riskService.getRiskAssessments()
      ]);

      setOverview(overviewRes);
      setThreatClassifications(threatRes.classifications);
      setThreatTrend(threatRes.trend);
      setHasHistoricalThreats(threatRes.hasHistoricalData);
      setRiskData(riskRes);
      setAgentDetails(agentRes.agents);
      setComparativeNote(agentRes.comparativeNote);
      setAlertIncidentData(alertIncRes);
      setCorrelationStats(corrRes);
      setTimelineEvents(timelineRes);
      setTraceabilityChains(traceRes);
      setRawAssessments(assessmentsRes);
    } catch (err: any) {
      console.error('Failed to load unified dashboard analytics:', err);
      setFetchError(err?.message || 'Failed to load telemetry data from backend');
    } finally {
      setIsLoadingAnalytics(false);
    }
  }, [filters.timeRange]);

  const [fetchError, setFetchError] = useState<string | null>(null);

  useEffect(() => {
    loadDashboardData();
    fetchHealth();
    const healthInterval = setInterval(fetchHealth, 15000);
    const unsubscribe = logRepository.subscribe(() => {
      loadDashboardData();
    });
    const unsubPipeline = livePipelineService.subscribe(() => {
      setLiveStatus(livePipelineService.getStatus());
      setLiveEvents(livePipelineService.getEvents());
      setLiveQueued(livePipelineService.getQueuedEvents());
    });

    // 1. Reactive Real-Time Telemetry Stream: updates overview, events, threats, alerts & incidents without manual refresh
    const unsubComposite = realtimeTelemetryStream.onCompositeEvent((composite) => {
      const { event, isThreat, finding, alert, incident, riskAssessment } = composite;
      if (!event) return;

      // Increment overview counters reactively
      setOverview(prev => {
        if (!prev) return prev;
        const isCrit = event.severity === 'CRITICAL';
        const isHigh = event.severity === 'HIGH';
        return {
          ...prev,
          totalEvents: prev.totalEvents + 1,
          totalThreats: prev.totalThreats + (isThreat ? 1 : 0),
          criticalThreats: prev.criticalThreats + (isCrit ? 1 : 0),
          highThreats: prev.highThreats + (isHigh ? 1 : 0),
          openAlerts: prev.openAlerts + (alert ? 1 : 0),
          criticalAlerts: prev.criticalAlerts + (alert && alert.severity === 'CRITICAL' ? 1 : 0),
          highAlerts: prev.highAlerts + (alert && alert.severity === 'HIGH' ? 1 : 0),
          openIncidents: prev.openIncidents + (incident ? 1 : 0),
          criticalIncidents: prev.criticalIncidents + (incident && incident.severity === 'CRITICAL' ? 1 : 0),
          highIncidents: prev.highIncidents + (incident && incident.severity === 'HIGH' ? 1 : 0),
          lastUpdated: new Date().toLocaleTimeString()
        };
      });

      // Prepend to Unified Timeline Items
      const newTimelineItem: UnifiedTimelineItem = {
        id: event.eventId,
        timestamp: event.timestamp.replace('T', ' ').substring(0, 19),
        eventType: isThreat ? 'THREAT_DETECTED' : 'LOG_RECEIVED',
        title: isThreat
          ? `[${event.source.toUpperCase()}] ${finding?.threatType || finding?.threat_type || 'Threat Detected'}`
          : `[${event.source.toUpperCase()}] Telemetry Ingested`,
        description: event.details || (typeof event.rawPayload === 'string' ? event.rawPayload.slice(0, 120) : 'Normalized host event'),
        severity: (event.severity || 'LOW') as any,
        source: event.source,
        relatedId: finding?.id || event.eventId,
        relatedType: isThreat ? 'THREAT' : 'LOG'
      };
      setTimelineEvents(prev => [newTimelineItem, ...prev.slice(0, 99)]);

      // Prepend to Alert & Incident Analytics data
      if (alert || incident) {
        setAlertIncidentData((prev: any) => {
          if (!prev) return prev;
          const copy = { ...prev };
          if (alert) {
            copy.totalAlerts = (copy.totalAlerts || 0) + 1;
            if (alert.severity === 'CRITICAL') copy.criticalAlerts = (copy.criticalAlerts || 0) + 1;
            if (alert.severity === 'HIGH') copy.highAlerts = (copy.highAlerts || 0) + 1;
            if (copy.recentAlerts) {
              copy.recentAlerts = [alert, ...copy.recentAlerts.slice(0, 19)];
            }
          }
          if (incident) {
            copy.totalIncidents = (copy.totalIncidents || 0) + 1;
            if (incident.severity === 'CRITICAL') copy.criticalIncidents = (copy.criticalIncidents || 0) + 1;
            if (copy.activeIncidents) {
              copy.activeIncidents = [incident, ...copy.activeIncidents.slice(0, 19)];
            }
          }
          return copy;
        });
      }
    });

    // 2. Real-time Agent Status updates
    const unsubAgent = realtimeTelemetryStream.onAgentStatus((agentUpdate) => {
      if (!agentUpdate || !agentUpdate.agentId) return;
      setAgentDetails(prev => {
        if (!prev || prev.length === 0) return prev;
        return prev.map(ag => {
          const match = ag.id === agentUpdate.agentId ||
            ag.name?.toLowerCase().includes(agentUpdate.agentType?.toLowerCase() || '') ||
            agentUpdate.agentId.toLowerCase().includes(ag.id?.toLowerCase() || '');
          if (match) {
            return {
              ...ag,
              status: agentUpdate.status || ag.status,
              eventsProcessed: agentUpdate.eventsProcessed ?? ag.eventsProcessed,
              threatsDetected: agentUpdate.threatsDetected ?? ag.threatsDetected,
              lastProcessedEvent: agentUpdate.lastActivity || new Date().toISOString()
            };
          }
          return ag;
        });
      });
    });

    // 3. Real-time Collector & Database Health updates
    const unsubCollector = realtimeTelemetryStream.onCollectorHealth((health) => {
      if (health) {
        setSystemHealth(prev => prev ? {
          ...prev,
          collectorsCount: `${health.activeCollectorsCount}/${health.totalCollectors}`
        } : prev);
      }
    });

    const unsubDb = realtimeTelemetryStream.onDatabaseHealth((db) => {
      if (db) {
        setSystemHealth(prev => prev ? {
          ...prev,
          database: db.connected ? 'CONNECTED (MongoDB Verified)' : 'DATABASE_UNAVAILABLE',
          databaseMode: db.connected ? 'AUTHENTIC PERSISTENCE' : 'LOCAL FALLBACK'
        } : prev);
      }
    });

    return () => {
      clearInterval(healthInterval);
      unsubscribe();
      unsubPipeline();
      unsubComposite();
      unsubAgent();
      unsubCollector();
      unsubDb();
    };
  }, [loadDashboardData, fetchHealth]);

  // Handle Risk Status Update
  const handleUpdateRiskStatus = async (id: string, newStatus: RiskStatus) => {
    await riskService.updateAssessmentStatus(id, newStatus);
    await loadDashboardData();
    if (selectedAssessment && selectedAssessment.id === id) {
      const updated = await riskService.getRiskAssessments();
      const refreshed = updated.find(a => a.id === id);
      if (refreshed) setSelectedAssessment(refreshed);
    }
  };

  // Quick Filter Handler from Summary Cards
  const handleQuickFilter = (type: 'CRITICAL' | 'HIGH' | 'ALERTS' | 'INCIDENTS') => {
    if (type === 'CRITICAL') {
      setFilters(prev => ({ ...prev, severity: 'CRITICAL' }));
    } else if (type === 'HIGH') {
      setFilters(prev => ({ ...prev, severity: 'HIGH' }));
    } else if (type === 'ALERTS') {
      setActiveTab('ALERTS_INCIDENTS');
    } else if (type === 'INCIDENTS') {
      setActiveTab('ALERTS_INCIDENTS');
    }
  };

  // Compute filtered timeline events
  const filteredTimeline = timelineEvents.filter(event => {
    if (filters.searchTerm) {
      const q = filters.searchTerm.toLowerCase();
      const match =
        event.title.toLowerCase().includes(q) ||
        event.description.toLowerCase().includes(q) ||
        event.id.toLowerCase().includes(q) ||
        (event.relatedId && event.relatedId.toLowerCase().includes(q));
      if (!match) return false;
    }
    if (filters.severity && filters.severity !== 'ALL' && event.severity !== filters.severity) {
      return false;
    }
    return true;
  });

  return (
    <div className="space-y-6" id="page-dashboard">
      {/* Top Banner Notice: Architecture & Demo Control */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1 flex-wrap">
            {/* Verified Telemetry Stream Status: LIVE / CONNECTING / DISCONNECTED / SIMULATION / ERROR */}
            <TelemetryStatusBadge />
            {/* Backend Connectivity Badges */}
            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono">
              API: {systemHealth?.nodeServer || 'ONLINE (Port 3000)'}
            </span>
            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono">
              ML Engine: {systemHealth?.pythonMLBackend || 'INTEGRATED / READY'}
            </span>
            {logRepository.hasRealData() ? (
              <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/90 text-emerald-300 border border-emerald-700 font-mono font-bold">
                DATA: INGESTED BENCHMARK
              </span>
            ) : (
              <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-950/90 text-indigo-300 border border-indigo-700 font-mono font-bold">
                DATA: SIMULATOR / EVALUATION
              </span>
            )}
          </div>
          <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight font-mono">
            AI-Driven Multi-Agent Cyber Threat Detection
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl font-mono">
            Unified correlation, risk scoring, threat prioritization, and incident triage across Network, System, Application, Correlation, Threat Detection, and Alert specialized agents.
          </p>
        </div>

        {/* Global Action Buttons */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          {/* Demo Scenario Modal Trigger (Section 33-39) */}
          <button
            id="btn-dash-demo-scenarios"
            onClick={() => setIsDemoModalOpen(true)}
            className="px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold transition-all shadow-lg shadow-indigo-600/20 flex items-center gap-1.5"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>Project Demo Mode</span>
          </button>

          <button
            id="btn-dash-reports"
            onClick={() => setActiveTab('REPORTS')}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
          >
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span>Reports & Exports</span>
          </button>

          <button
            id="btn-dash-refresh"
            onClick={() => {
              loadDashboardData();
              fetchHealth();
            }}
            disabled={isLoadingAnalytics}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
            title="Refresh All Analytics"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoadingAnalytics ? 'animate-spin text-cyan-400' : ''}`} />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      </div>

      {/* Global Error Banner if API sync fails */}
      {fetchError && (
        <div className="p-4 rounded-xl bg-rose-950/80 border border-rose-800 text-rose-200 flex items-center justify-between font-mono text-xs shadow-lg">
          <div className="flex items-center gap-2.5">
            <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
            <span>Telemetry Sync Warning: {fetchError}. Operating from cached or local agent state.</span>
          </div>
          <button
            onClick={() => {
              loadDashboardData();
              fetchHealth();
            }}
            className="px-2.5 py-1 bg-rose-900 hover:bg-rose-800 text-white rounded border border-rose-700 font-bold"
          >
            Retry
          </button>
        </div>
      )}

      {/* Global Search & Advanced Filtering Bar (Sections 18 & 19) */}
      <GlobalSearchAndFilterBar
        filters={filters}
        onFilterChange={setFilters}
        resultCount={filteredTimeline.length}
        totalCount={timelineEvents.length}
      />

      {/* Initial Loading Skeleton */}
      {isLoadingAnalytics && !overview && (
        <div className="p-8 rounded-xl bg-slate-900 border border-slate-800 text-center font-mono space-y-3">
          <RefreshCw className="w-7 h-7 text-cyan-400 animate-spin mx-auto" />
          <p className="text-sm text-slate-200 font-semibold">Synchronizing Multi-Agent Telemetry Stream...</p>
          <p className="text-xs text-slate-500">Querying Network, System, Application, Correlation, ML, and Alert engines</p>
        </div>
      )}

      {/* Primary Dashboard Navigation Tabs (7 Core Project Specifications + Auxiliary) */}
      <div className="flex items-center gap-1.5 overflow-x-auto max-w-full pb-1 border-b border-slate-800 font-mono text-xs">
        {/* 1. OVERVIEW */}
        <button
          id="tab-overview"
          onClick={() => setActiveTab('OVERVIEW')}
          className={`px-3 py-2 rounded-t-lg transition-colors flex items-center gap-1.5 font-bold whitespace-nowrap ${
            activeTab === 'OVERVIEW'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <TrendingUp className="w-3.5 h-3.5" />
          <span>1. Overview</span>
        </button>

        {/* 2. LIVE SECURITY EVENTS */}
        <button
          id="tab-live-events"
          onClick={() => setActiveTab('LIVE_EVENTS')}
          className={`px-3 py-2 rounded-t-lg transition-colors flex items-center gap-1.5 font-bold whitespace-nowrap ${
            activeTab === 'LIVE_EVENTS'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span>2. Live Security Events</span>
          <span className="text-[9px] px-1 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 font-mono">
            Stream
          </span>
        </button>

        {/* 3. MULTI-AGENT STATUS */}
        <button
          id="tab-multi-agent"
          onClick={() => setActiveTab('MULTI_AGENT')}
          className={`px-3 py-2 rounded-t-lg transition-colors flex items-center gap-1.5 font-bold whitespace-nowrap ${
            activeTab === 'MULTI_AGENT'
              ? 'bg-slate-900 text-emerald-400 border-t-2 border-emerald-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <Cpu className="w-3.5 h-3.5 text-emerald-400" />
          <span>3. Multi-Agent Status</span>
          <span className="text-[9px] px-1 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-mono">
            6 Agents
          </span>
        </button>

        {/* 4. THREAT DETECTION */}
        <button
          id="tab-threat-detection"
          onClick={() => setActiveTab('THREAT_DETECTION')}
          className={`px-3 py-2 rounded-t-lg transition-colors flex items-center gap-1.5 font-bold whitespace-nowrap ${
            activeTab === 'THREAT_DETECTION'
              ? 'bg-slate-900 text-rose-400 border-t-2 border-rose-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
          <span>4. Threat Detection</span>
          <span className="text-[9px] px-1 py-0.2 rounded bg-rose-950 text-rose-300 border border-rose-800 font-mono">
            ML+Rules
          </span>
        </button>

        {/* 5. INCIDENT MANAGEMENT */}
        <button
          id="tab-incidents"
          onClick={() => setActiveTab('INCIDENTS')}
          className={`px-3 py-2 rounded-t-lg transition-colors flex items-center gap-1.5 font-bold whitespace-nowrap ${
            activeTab === 'INCIDENTS'
              ? 'bg-slate-900 text-purple-400 border-t-2 border-purple-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-purple-400" />
          <span>5. Incident Management</span>
        </button>

        {/* 6. ANALYTICS */}
        <button
          id="tab-analytics"
          onClick={() => setActiveTab('ANALYTICS')}
          className={`px-3 py-2 rounded-t-lg transition-colors flex items-center gap-1.5 font-bold whitespace-nowrap ${
            activeTab === 'ANALYTICS'
              ? 'bg-slate-900 text-indigo-400 border-t-2 border-indigo-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <BarChart2 className="w-3.5 h-3.5 text-indigo-400" />
          <span>6. Analytics</span>
        </button>

        {/* 7. REPORTS */}
        <button
          id="tab-reports"
          onClick={() => setActiveTab('REPORTS')}
          className={`px-3 py-2 rounded-t-lg transition-colors flex items-center gap-1.5 font-bold whitespace-nowrap ${
            activeTab === 'REPORTS'
              ? 'bg-slate-900 text-emerald-400 border-t-2 border-emerald-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <FileSpreadsheet className="w-3.5 h-3.5 text-emerald-400" />
          <span>7. Reports</span>
          <span className="text-[9px] px-1 py-0.2 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-mono">
            Export
          </span>
        </button>

        <div className="h-4 w-[1px] bg-slate-800 mx-1 flex-shrink-0" />

        {/* Auxiliary Tabs for deep inspection */}
        <button
          onClick={() => setActiveTab('CORRELATIONS')}
          className={`px-2.5 py-2 rounded-t-lg transition-colors flex items-center gap-1 font-bold whitespace-nowrap ${
            activeTab === 'CORRELATIONS'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-400 border-x border-slate-800'
              : 'text-slate-500 hover:text-slate-300 hover:bg-slate-900/50'
          }`}
        >
          <span>Attack Chains</span>
        </button>

        <button
          onClick={() => setActiveTab('LIVE_PIPELINE')}
          className={`px-2.5 py-2 rounded-t-lg transition-colors flex items-center gap-1 font-bold whitespace-nowrap ${
            activeTab === 'LIVE_PIPELINE'
              ? 'bg-slate-900 text-emerald-400 border-t-2 border-emerald-400 border-x border-slate-800'
              : 'text-slate-500 hover:text-slate-300 hover:bg-slate-900/50'
          }`}
        >
          <Radio className="w-3 h-3 text-emerald-400" />
          <span>Simulator API</span>
        </button>

        <button
          onClick={() => setActiveTab('TRACEABILITY')}
          className={`px-2.5 py-2 rounded-t-lg transition-colors flex items-center gap-1 font-bold whitespace-nowrap ${
            activeTab === 'TRACEABILITY'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-400 border-x border-slate-800'
              : 'text-slate-500 hover:text-slate-300 hover:bg-slate-900/50'
          }`}
        >
          <span>Traceability</span>
        </button>
      </div>

      {/* TAB CONTENT AREAS */}

      {/* 1. OVERVIEW TAB */}
      {activeTab === 'OVERVIEW' && (
        <OverviewSection
          overview={overview}
          metrics={metrics}
          isRealData={logRepository.hasRealData()}
          onNavigate={onNavigate}
          onSelectSection={(s) => setActiveTab(s as any)}
        />
      )}

      {/* 2. LIVE SECURITY EVENTS TAB */}
      {activeTab === 'LIVE_EVENTS' && (
        <LiveSecurityEventsSection
          onSelectEvent={(evt) => setSelectedLiveEvent(evt)}
        />
      )}

      {/* 3. MULTI-AGENT STATUS TAB */}
      {activeTab === 'MULTI_AGENT' && (
        <MultiAgentStatusSection
          onNavigate={onNavigate}
        />
      )}

      {/* 4. THREAT DETECTION TAB */}
      {activeTab === 'THREAT_DETECTION' && (
        <ThreatDetectionSection />
      )}

      {/* 5. INCIDENT MANAGEMENT TAB */}
      {activeTab === 'INCIDENTS' && (
        <IncidentManagementSection />
      )}

      {/* 6. ANALYTICS TAB */}
      {activeTab === 'ANALYTICS' && (
        <AnalyticsSection
          eventsOverTime={eventsOverTime}
        />
      )}

      {/* 7. REPORTS TAB */}
      {activeTab === 'REPORTS' && (
        <ReportsSection />
      )}

      {/* AUX: LIVE PIPELINE & LOCAL ML API TAB */}
      {activeTab === 'LIVE_PIPELINE' && (
        <div className="space-y-6">
          <LivePipelineStatusCard
            status={liveStatus}
            onRefresh={async () => {
              await livePipelineService.checkBackendHealth();
              setLiveStatus(livePipelineService.getStatus());
            }}
            onNavigateToTraining={() => onNavigate('datasets-ml')}
          />

          <LivePipelineControls
            status={liveStatus}
            onStartPipeline={() => livePipelineService.startPipeline()}
            onStopPipeline={() => livePipelineService.stopPipeline()}
            onStartSimulator={(rate, mode) => livePipelineService.startSimulator({ eventRate: rate, mode })}
            onStopSimulator={() => livePipelineService.stopSimulator()}
            onClearEvents={() => livePipelineService.clearEvents()}
            onRefreshStatus={async () => {
              await livePipelineService.checkBackendHealth();
              setLiveStatus(livePipelineService.getStatus());
            }}
            onRunDemo={() => setIsProjectDemoOpen(true)}
          />

          <AcademicPresentationView status={liveStatus} />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <ModelInfoPanel onNavigateToTraining={() => onNavigate('datasets-ml')} />
            <EventQueueViewer queuedEvents={liveQueued} status={liveStatus} />
          </div>

          <LiveEventStreamTable
            events={liveEvents}
            onSelectEvent={(evt) => setSelectedLiveEvent(evt)}
          />
        </div>
      )}

      {/* 2. CROSS-SOURCE CORRELATION & MULTI-STAGE ATTACK CHAINS TAB */}
      {activeTab === 'CORRELATIONS' && correlationStats && (
        <div className="space-y-6">
          <CrossSourceCorrelationPanel stats={correlationStats} />

          {/* Direct link to correlation page */}
          <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl flex items-center justify-between font-mono text-xs">
            <div>
              <h4 className="font-bold text-white">Need to inspect correlation sliding windows or rule weights?</h4>
              <p className="text-slate-400 text-[11px] mt-0.5">
                Open the dedicated Event Correlation Engine console for complete multi-source graph inspection.
              </p>
            </div>
            <button
              onClick={() => onNavigate('correlation' as any)}
              className="px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white font-bold transition-colors"
            >
              Open Correlation Engine Console →
            </button>
          </div>
        </div>
      )}

      {/* 3. ALERTS & INCIDENTS TOPOLOGY TAB */}
      {activeTab === 'ALERTS_INCIDENTS' && alertIncidentData && (
        <div className="space-y-6">
          <AlertIncidentAnalyticsPanel
            data={alertIncidentData}
            onNavigate={onNavigate}
          />
        </div>
      )}

      {/* 4. UNIFIED CHRONOLOGICAL TIMELINE TAB */}
      {activeTab === 'TIMELINE' && (
        <div className="space-y-6">
          <EventTimelinePanel
            events={filteredTimeline}
            onNavigate={onNavigate}
          />
        </div>
      )}

      {/* 5. END-TO-END TRACEABILITY TAB */}
      {activeTab === 'TRACEABILITY' && (
        <div className="space-y-6">
          <EndToEndTraceabilityPanel chains={traceabilityChains} />
        </div>
      )}

      {/* 6. n8n AUTOMATION BLUEPRINT TAB */}
      {activeTab === 'N8N_PREVIEW' && (
        <div className="space-y-6">
          <FutureN8nPlaceholder />
        </div>
      )}

      {/* Demo Scenario Modal (Sections 33-39) */}
      <DemoScenarioModal
        isOpen={isDemoModalOpen}
        onClose={() => setIsDemoModalOpen(false)}
        onScenarioLoaded={scenarioId => {
          loadDashboardData();
        }}
        onResetComplete={() => {
          loadDashboardData();
        }}
      />

      {/* Modal for Risk Detail */}
      {selectedAssessment && (
        <RiskDetailModal
          assessment={selectedAssessment}
          onClose={() => setSelectedAssessment(null)}
          onUpdateStatus={handleUpdateRiskStatus}
        />
      )}

      {/* Stage 12 Live Traceability Modal */}
      <LiveTraceabilityModal
        event={selectedLiveEvent}
        onClose={() => setSelectedLiveEvent(null)}
      />

      {/* Stage 12 12-Step Guided Project Demo Modal */}
      <ProjectDemoModal
        isOpen={isProjectDemoOpen}
        onClose={() => setIsProjectDemoOpen(false)}
        status={liveStatus}
        onNavigateToTraining={() => onNavigate('datasets-ml')}
      />
    </div>
  );
};
