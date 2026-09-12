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
  RotateCcw
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

type DashboardTab = 'OVERVIEW' | 'CORRELATIONS' | 'ALERTS_INCIDENTS' | 'TIMELINE' | 'TRACEABILITY' | 'N8N_PREVIEW';

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

  // Load all analytics from unifiedAnalyticsService
  const loadDashboardData = useCallback(async () => {
    setIsLoadingAnalytics(true);
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
    } catch (err) {
      console.error('Failed to load unified dashboard analytics:', err);
    } finally {
      setIsLoadingAnalytics(false);
    }
  }, [filters.timeRange]);

  useEffect(() => {
    loadDashboardData();
    const unsubscribe = logRepository.subscribe(() => {
      loadDashboardData();
    });
    return () => unsubscribe();
  }, [loadDashboardData]);

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
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-xs font-mono uppercase tracking-widest text-cyan-400 font-semibold">
              Advanced SOC Telemetry & Intelligence Stream
            </span>
          </div>
          <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight font-mono">
            AI-Driven Multi-Agent Cyber Threat Detection
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl font-mono">
            Unified correlation, risk scoring, threat prioritization, and incident triage across Network, System, and Application specialized agents.
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
            onClick={() => onNavigate('reports' as any)}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
          >
            <FileText className="w-3.5 h-3.5 text-cyan-400" />
            <span>Reports & Exports</span>
          </button>

          <button
            id="btn-dash-refresh"
            onClick={() => loadDashboardData()}
            disabled={isLoadingAnalytics}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors flex items-center gap-1.5"
            title="Refresh All Analytics"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoadingAnalytics ? 'animate-spin text-cyan-400' : ''}`} />
            <span className="hidden sm:inline">Refresh</span>
          </button>
        </div>
      </div>

      {/* Global Search & Advanced Filtering Bar (Sections 18 & 19) */}
      <GlobalSearchAndFilterBar
        filters={filters}
        onFilterChange={setFilters}
        resultCount={filteredTimeline.length}
        totalCount={timelineEvents.length}
      />

      {/* Top-Level Security Overview Cards (Section 4, 42, 43, 37) */}
      {overview && (
        <SecurityOverviewCards
          overview={overview}
          isRealData={logRepository.hasRealData()}
          onNavigate={onNavigate}
          onSelectQuickFilter={handleQuickFilter}
        />
      )}

      {/* Primary Dashboard Navigation Tabs (Stage 10 Structural Architecture) */}
      <div className="flex items-center gap-1.5 overflow-x-auto max-w-full pb-1 border-b border-slate-800 font-mono text-xs">
        <button
          onClick={() => setActiveTab('OVERVIEW')}
          className={`px-3.5 py-2 rounded-t-lg transition-colors flex items-center gap-2 font-bold whitespace-nowrap ${
            activeTab === 'OVERVIEW'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <TrendingUp className="w-4 h-4" />
          <span>Security & Threat Analytics</span>
        </button>

        <button
          onClick={() => setActiveTab('CORRELATIONS')}
          className={`px-3.5 py-2 rounded-t-lg transition-colors flex items-center gap-2 font-bold whitespace-nowrap ${
            activeTab === 'CORRELATIONS'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <Layers className="w-4 h-4" />
          <span>Multi-Stage Attack Chains</span>
        </button>

        <button
          onClick={() => setActiveTab('ALERTS_INCIDENTS')}
          className={`px-3.5 py-2 rounded-t-lg transition-colors flex items-center gap-2 font-bold whitespace-nowrap ${
            activeTab === 'ALERTS_INCIDENTS'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>Alert & Incident Topology</span>
        </button>

        <button
          onClick={() => setActiveTab('TIMELINE')}
          className={`px-3.5 py-2 rounded-t-lg transition-colors flex items-center gap-2 font-bold whitespace-nowrap ${
            activeTab === 'TIMELINE'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <Clock className="w-4 h-4" />
          <span>Unified Event Timeline</span>
        </button>

        <button
          onClick={() => setActiveTab('TRACEABILITY')}
          className={`px-3.5 py-2 rounded-t-lg transition-colors flex items-center gap-2 font-bold whitespace-nowrap ${
            activeTab === 'TRACEABILITY'
              ? 'bg-slate-900 text-cyan-400 border-t-2 border-cyan-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <Radio className="w-4 h-4" />
          <span>End-to-End Traceability</span>
        </button>

        <button
          onClick={() => setActiveTab('N8N_PREVIEW')}
          className={`px-3.5 py-2 rounded-t-lg transition-colors flex items-center gap-2 font-bold whitespace-nowrap ${
            activeTab === 'N8N_PREVIEW'
              ? 'bg-slate-900 text-indigo-400 border-t-2 border-indigo-400 border-x border-slate-800'
              : 'text-slate-400 hover:text-white hover:bg-slate-900/50'
          }`}
        >
          <Workflow className="w-4 h-4" />
          <span>n8n Automation Blueprint</span>
        </button>
      </div>

      {/* TAB CONTENT AREAS */}

      {/* 1. OVERVIEW & ANALYTICS TAB */}
      {activeTab === 'OVERVIEW' && (
        <div className="space-y-6">
          {/* Threat Analytics (Sections 5 & 6) */}
          <ThreatAnalyticsPanel
            classifications={threatClassifications}
            trend={threatTrend}
            hasHistoricalData={hasHistoricalThreats}
            activeTimeRange={filters.timeRange}
            onTimeRangeChange={range => setFilters(prev => ({ ...prev, timeRange: range }))}
            evaluationMetrics={{
              isAvailable: false // Section 44: Explicitly not available
            }}
          />

          {/* Risk Analytics (Sections 7, 8, 9, 10) */}
          {riskData && (
            <RiskAnalyticsPanel
              riskData={riskData}
              assessments={rawAssessments}
              onSelectRisk={assessment => setSelectedAssessment(assessment)}
            />
          )}

          {/* Multi-Agent Activity Panel (Sections 11 & 12) */}
          {agentDetails.length > 0 && (
            <MultiAgentActivityPanel
              agents={agentDetails}
              comparativeNote={comparativeNote}
              onNavigate={onNavigate}
            />
          )}

          {/* Legacy Recent Telemetry Table for continuity */}
          <section aria-label="Recent Security Events" id="section-recent-events">
            <div className="flex items-center justify-between mb-3 font-mono">
              <div>
                <h3 className="text-sm font-bold text-white tracking-tight flex items-center gap-2">
                  <Activity className="w-4 h-4 text-cyan-400" />
                  REAL-TIME TELEMETRY EVENT STREAM
                </h3>
                <p className="text-xs text-slate-400">
                  Ingested security events with active agent validation and containment state.
                </p>
              </div>
              <button
                onClick={() => onNavigate('threat-detection')}
                className="text-xs text-cyan-400 hover:text-cyan-300 underline underline-offset-4"
              >
                Explore All Detections →
              </button>
            </div>

            <RecentEventsTable events={recentEvents} />
          </section>
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
    </div>
  );
};
