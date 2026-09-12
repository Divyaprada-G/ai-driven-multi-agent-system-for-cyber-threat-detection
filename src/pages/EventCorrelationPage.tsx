import React, { useState, useEffect, useCallback } from 'react';
import {
  GitMerge,
  ShieldAlert,
  Cpu,
  Network,
  Globe,
  Flame,
  Layers,
  CheckCircle2,
  Sliders,
  Filter,
  Search,
  RefreshCw,
  HardDrive,
  Server,
  User,
  Clock,
  Eye,
  AlertTriangle,
  FileText
} from 'lucide-react';
import { CorrelatedEvent, CorrelationMetrics, CorrelationScenarioId, CorrelationStrength, SeverityLevel, AgentType } from '../types';
import { correlationService } from '../services/correlationService';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { CorrelationGraph } from '../components/correlation/CorrelationGraph';
import { CorrelationTimeline } from '../components/correlation/CorrelationTimeline';
import { CorrelationEvidencePanel } from '../components/correlation/CorrelationEvidencePanel';
import { CorrelationDetailModal } from '../components/correlation/CorrelationDetailModal';
import { CORRELATION_DEMO_SCENARIOS } from '../services/correlationDemoScenarios';

export const EventCorrelationPage: React.FC = () => {
  const [correlations, setCorrelations] = useState<CorrelatedEvent[]>([]);
  const [metrics, setMetrics] = useState<CorrelationMetrics | null>(null);
  const [selectedCorrelation, setSelectedCorrelation] = useState<CorrelatedEvent | null>(null);
  const [modalEvent, setModalEvent] = useState<CorrelatedEvent | null>(null);
  const [activeScenario, setActiveScenario] = useState<CorrelationScenarioId | 'UPLOADED'>('DEMO_1');
  const [isRealData, setIsRealData] = useState(false);

  // Filters & Search
  const [searchQuery, setSearchQuery] = useState('');
  const [strengthFilter, setStrengthFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [agentFilter, setAgentFilter] = useState<string>('ALL');

  // Quick config modal
  const [showConfigDrawer, setShowConfigDrawer] = useState(false);
  const [configTimeWindow, setConfigTimeWindow] = useState(300);
  const [configMinFindings, setConfigMinFindings] = useState(2);
  const [configCrossAgent, setConfigCrossAgent] = useState(false);
  const [configMinStrength, setConfigMinStrength] = useState<CorrelationStrength>('LOW');

  const loadData = useCallback(async () => {
    const data = await correlationService.getCorrelatedEvents();
    const met = await correlationService.getMetrics();
    const real = correlationService.isRealDataActive();
    const currentScenario = correlationService.getCurrentScenarioId();

    setCorrelations(data);
    setMetrics(met);
    setIsRealData(real);
    setActiveScenario(real ? 'UPLOADED' : (currentScenario || 'DEMO_1'));

    if (data.length > 0) {
      setSelectedCorrelation(prev => {
        if (!prev) return data[0];
        const match = data.find(d => d.id === prev.id || d.correlationId === prev.correlationId);
        return match || data[0];
      });
    } else {
      setSelectedCorrelation(null);
    }

    const cfg = correlationService.getConfig();
    setConfigTimeWindow(cfg.timeWindowSeconds);
    setConfigMinFindings(cfg.minFindings);
    setConfigCrossAgent(cfg.crossAgentRequired);
    setConfigMinStrength(cfg.minCorrelationStrength);
  }, []);

  useEffect(() => {
    loadData();
    const unsubscribe = correlationService.subscribe(() => {
      loadData();
    });
    return unsubscribe;
  }, [loadData]);

  const handleScenarioChange = async (scenario: string) => {
    if (scenario === 'UPLOADED') {
      await correlationService.resetToDefaultDataSource();
    } else {
      await correlationService.loadDemoScenario(scenario as CorrelationScenarioId);
    }
    await loadData();
  };

  const handleSaveConfig = () => {
    correlationService.updateConfig({
      timeWindowSeconds: configTimeWindow,
      minFindings: configMinFindings,
      crossAgentRequired: configCrossAgent,
      minCorrelationStrength: configMinStrength
    });
    setShowConfigDrawer(false);
  };

  const handleEscalate = async (id: string) => {
    await correlationService.escalateToIncident(id);
    await loadData();
  };

  // Filter correlations
  const filteredCorrelations = correlations.filter(c => {
    if (strengthFilter !== 'ALL' && c.correlationStrength !== strengthFilter) return false;
    if (severityFilter !== 'ALL' && c.severity !== severityFilter) return false;
    if (agentFilter !== 'ALL' && !c.participatingAgents.includes(agentFilter as AgentType)) return false;

    if (searchQuery.trim().length > 0) {
      const q = searchQuery.toLowerCase();
      const matchText = [
        c.id,
        c.title,
        c.summary,
        c.description,
        ...c.sourceIps,
        ...c.hosts,
        ...c.users,
        ...c.threatTypes
      ].join(' ').toLowerCase();
      if (!matchText.includes(q)) return false;
    }

    return true;
  });

  return (
    <div className="space-y-6" id="page-event-correlation">
      {/* 18. HEADER & ENGINE STATUS */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest font-semibold flex items-center gap-1.5">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
              Multi-Agent Telemetry Synthesis
            </span>
            <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 font-mono text-[10px] font-bold">
              STATUS: READY
            </span>
            <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold border ${
              isRealData
                ? 'bg-cyan-950 text-cyan-300 border-cyan-800'
                : 'bg-amber-950 text-amber-300 border-amber-800'
            }`}>
              DATA SOURCE: {isRealData ? 'UPLOADED DATA' : 'DEMO DATA'}
            </span>
          </div>

          <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight mt-1 flex items-center gap-2">
            <GitMerge className="w-6 h-6 text-cyan-400" />
            Event Correlation Engine
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Correlates specialized signals from Network, System, and Application agents across time proximity, shared IPs, hosts, credentials, and multi-stage attack progressions.
          </p>
        </div>

        {/* Action Controls & Scenario Selector */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div className="flex items-center gap-1.5 bg-slate-900 border border-slate-800 rounded-lg p-1">
            <span className="text-[11px] font-mono text-slate-400 px-2 font-semibold">Scenario:</span>
            <select
              id="select-correlation-scenario"
              value={activeScenario}
              onChange={e => handleScenarioChange(e.target.value)}
              aria-label="Select Correlation Scenario"
              className="bg-slate-950 text-slate-200 border border-slate-700 text-xs font-mono rounded px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              {isRealData && <option value="UPLOADED">Active Uploaded Ingestion Data</option>}
              <option value="DEMO_1">DEMO 1: Cross-Agent Intrusion (Network+System+App)</option>
              <option value="DEMO_2">DEMO 2: Auth Abuse & Privilege Escalation (Host)</option>
              <option value="DEMO_3">DEMO 3: Coordinated Activity (Web API + Traffic Flood)</option>
              <option value="DEMO_4">DEMO 4: Unrelated Events (Zero Correlation / Negative Test)</option>
            </select>
          </div>

          <button
            id="btn-correlation-settings"
            onClick={() => setShowConfigDrawer(!showConfigDrawer)}
            className="px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 rounded-lg text-xs font-mono font-semibold flex items-center gap-1.5 transition-colors"
          >
            <Sliders className="w-3.5 h-3.5 text-cyan-400" />
            <span>Rules Config</span>
          </button>
        </div>
      </div>

      {/* 23. QUICK CONFIG DRAWER / PANEL */}
      {showConfigDrawer && (
        <div className="p-4 sm:p-5 bg-slate-950 border border-cyan-500/30 rounded-xl space-y-4 animate-in fade-in duration-200" id="panel-correlation-config">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-300 flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                Correlation Engine Configuration Parameters
              </h4>
              <p className="text-[11px] text-slate-400">
                Adjust sensitivity parameters. Changes immediately trigger mathematical re-clustering.
              </p>
            </div>
            <button
              id="btn-close-config-drawer"
              onClick={() => setShowConfigDrawer(false)}
              className="text-xs font-mono text-slate-400 hover:text-white"
            >
              Close
            </button>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 text-xs font-mono">
            {/* Time Window */}
            <div className="space-y-1.5">
              <label htmlFor="config-time-window" className="text-slate-300 font-semibold block">
                Time Window (Seconds)
              </label>
              <select
                id="config-time-window"
                value={configTimeWindow}
                onChange={e => setConfigTimeWindow(Number(e.target.value))}
                className="w-full bg-slate-900 border border-slate-700 text-slate-200 rounded-lg p-2 focus:border-cyan-500"
              >
                <option value={30}>30 Seconds (Strict Burst)</option>
                <option value={60}>60 Seconds (1 Minute)</option>
                <option value={300}>300 Seconds (5 Minutes Standard)</option>
                <option value={900}>900 Seconds (15 Minutes Extended)</option>
              </select>
            </div>

            {/* Minimum Findings */}
            <div className="space-y-1.5">
              <label htmlFor="config-min-findings" className="text-slate-300 font-semibold block">
                Minimum Findings
              </label>
              <select
                id="config-min-findings"
                value={configMinFindings}
                onChange={e => setConfigMinFindings(Number(e.target.value))}
                className="w-full bg-slate-900 border border-slate-700 text-slate-200 rounded-lg p-2 focus:border-cyan-500"
              >
                <option value={2}>2 Findings (Standard Cluster)</option>
                <option value={3}>3 Findings (Triad Multi-Signal)</option>
                <option value={4}>4 Findings (Deep Forensic Chain)</option>
              </select>
            </div>

            {/* Cross Agent Required */}
            <div className="space-y-1.5">
              <label htmlFor="config-cross-agent" className="text-slate-300 font-semibold block">
                Cross-Agent Requirement
              </label>
              <select
                id="config-cross-agent"
                value={configCrossAgent ? 'true' : 'false'}
                onChange={e => setConfigCrossAgent(e.target.value === 'true')}
                className="w-full bg-slate-900 border border-slate-700 text-slate-200 rounded-lg p-2 focus:border-cyan-500"
              >
                <option value="false">Allow Single Domain Sequences</option>
                <option value="true">Require 2+ Distinct Agents (Strict)</option>
              </select>
            </div>

            {/* Minimum Strength */}
            <div className="space-y-1.5">
              <label htmlFor="config-min-strength" className="text-slate-300 font-semibold block">
                Minimum Correlation Strength
              </label>
              <select
                id="config-min-strength"
                value={configMinStrength}
                onChange={e => setConfigMinStrength(e.target.value as CorrelationStrength)}
                className="w-full bg-slate-900 border border-slate-700 text-slate-200 rounded-lg p-2 focus:border-cyan-500"
              >
                <option value="LOW">LOW (Confidence ≥ 15%)</option>
                <option value="MEDIUM">MEDIUM (Confidence ≥ 50%)</option>
                <option value="HIGH">HIGH (Confidence ≥ 75%)</option>
              </select>
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
            <button
              id="btn-apply-config"
              onClick={handleSaveConfig}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-mono font-bold transition-colors shadow-sm"
            >
              Apply & Re-Correlate
            </button>
          </div>
        </div>
      )}

      {/* 18. METRICS BAR (7 Core Metrics) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block truncate">
            Total Findings
          </span>
          <div className="text-lg font-bold text-white font-mono">
            {metrics?.totalFindings || 0}
          </div>
        </div>

        <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 block truncate font-semibold">
            Correlated Events
          </span>
          <div className="text-lg font-bold text-cyan-400 font-mono">
            {metrics?.correlatedEventsCount || 0}
          </div>
        </div>

        <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-purple-400 block truncate">
            Cross-Agent Links
          </span>
          <div className="text-lg font-bold text-purple-400 font-mono">
            {metrics?.crossAgentCorrelationsCount || 0}
          </div>
        </div>

        <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-rose-400 block truncate">
            High-Strength
          </span>
          <div className="text-lg font-bold text-rose-400 font-mono">
            {metrics?.highStrengthCorrelationsCount || 0}
          </div>
        </div>

        <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block truncate">
            Unique Source IPs
          </span>
          <div className="text-lg font-bold text-slate-200 font-mono">
            {metrics?.uniqueSourceIpsCount || 0}
          </div>
        </div>

        <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block truncate">
            Affected Hosts
          </span>
          <div className="text-lg font-bold text-slate-200 font-mono">
            {metrics?.affectedHostsCount || 0}
          </div>
        </div>

        <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
          <span className="text-[10px] font-mono uppercase tracking-wider text-slate-400 block truncate">
            Affected Users
          </span>
          <div className="text-lg font-bold text-slate-200 font-mono">
            {metrics?.affectedUsersCount || 0}
          </div>
        </div>
      </div>

      {/* 20. ACTIVE CORRELATED INCIDENT FOCUS (Topology + Timeline + Evidence) */}
      {selectedCorrelation && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Active Incident Focus: <span className="text-cyan-400">{selectedCorrelation.id}</span>
            </h3>
            <button
              id="btn-open-full-detail"
              onClick={() => setModalEvent(selectedCorrelation)}
              className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
            >
              <Eye className="w-3.5 h-3.5" />
              <span>Deep Forensic Inspection</span>
            </button>
          </div>

          {/* Graph Visualization */}
          <CorrelationGraph correlatedEvent={selectedCorrelation} />

          {/* Timeline & Evidence Panel Side by Side on large screens */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <CorrelationTimeline
              correlatedEvent={selectedCorrelation}
              onEscalate={() => handleEscalate(selectedCorrelation.id)}
            />
            <CorrelationEvidencePanel correlatedEvent={selectedCorrelation} />
          </div>
        </div>
      )}

      {/* 19. CORRELATED EVENTS TABLE & FILTERS */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-xl overflow-hidden shadow-lg">
        <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <GitMerge className="w-4 h-4 text-cyan-400" />
              Correlated Event Clusters ({filteredCorrelations.length})
            </h3>
            <p className="text-xs text-slate-400">
              Deterministic clusters constructed via multi-agent temporal and entity linkage.
            </p>
          </div>

          {/* Search and Filters */}
          <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                id="input-search-correlation"
                type="text"
                placeholder="Search IP, host, title..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 text-xs focus:outline-none focus:border-cyan-500 w-44 sm:w-56"
              />
            </div>

            {/* Strength Filter */}
            <select
              id="filter-strength"
              value={strengthFilter}
              onChange={e => setStrengthFilter(e.target.value)}
              aria-label="Filter by Correlation Strength"
              className="bg-slate-950 border border-slate-800 text-slate-300 rounded-lg px-2.5 py-1.5 focus:border-cyan-500 cursor-pointer"
            >
              <option value="ALL">All Strengths</option>
              <option value="HIGH">High Strength</option>
              <option value="MEDIUM">Medium Strength</option>
              <option value="LOW">Low Strength</option>
            </select>

            {/* Severity Filter */}
            <select
              id="filter-severity"
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              aria-label="Filter by Threat Severity"
              className="bg-slate-950 border border-slate-800 text-slate-300 rounded-lg px-2.5 py-1.5 focus:border-cyan-500 cursor-pointer"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>

            {/* Agent Filter */}
            <select
              id="filter-agent"
              value={agentFilter}
              onChange={e => setAgentFilter(e.target.value)}
              aria-label="Filter by Agent Domain"
              className="bg-slate-950 border border-slate-800 text-slate-300 rounded-lg px-2.5 py-1.5 focus:border-cyan-500 cursor-pointer"
            >
              <option value="ALL">All Agents</option>
              <option value="NETWORK_AGENT">Network Agent</option>
              <option value="SYSTEM_AGENT">System Agent</option>
              <option value="APPLICATION_AGENT">Application Agent</option>
            </select>
          </div>
        </div>

        {filteredCorrelations.length === 0 ? (
          <div className="p-8 sm:p-12 text-center space-y-3 bg-slate-950/60" id="empty-correlations-state">
            <div className="w-12 h-12 rounded-2xl bg-slate-900 border border-slate-800 flex items-center justify-center mx-auto text-slate-500">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <h4 className="text-sm font-bold text-white font-mono">
              No Correlated Threat Sequences Detected
            </h4>
            <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
              Observed findings did not meet the active temporal window or shared entity thresholds. Unrelated events remain isolated to eliminate false-positive alert fatigue.
            </p>
            {activeScenario === 'DEMO_4' && (
              <div className="p-3 bg-cyan-950/40 border border-cyan-800/80 rounded-lg max-w-lg mx-auto text-xs font-mono text-cyan-300">
                Academic Verification: DEMO 4 correctly demonstrates negative testing behavior where unrelated events from distinct IPs, hosts, and timestamps are not erroneously merged.
              </div>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs text-slate-300 font-mono">
              <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Correlation ID</th>
                  <th className="py-3 px-4">Window / Duration</th>
                  <th className="py-3 px-4">Agents</th>
                  <th className="py-3 px-4">Attack Pattern</th>
                  <th className="py-3 px-4">Source</th>
                  <th className="py-3 px-4">Target</th>
                  <th className="py-3 px-4">Strength</th>
                  <th className="py-3 px-4">Confidence</th>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredCorrelations.map(corr => {
                  const isSelected = selectedCorrelation?.id === corr.id;
                  return (
                    <tr
                      key={corr.id}
                      id={`row-corr-${corr.id.toLowerCase()}`}
                      onClick={() => setSelectedCorrelation(corr)}
                      className={`cursor-pointer transition-colors ${
                        isSelected ? 'bg-slate-800/70 border-l-2 border-l-cyan-400' : 'hover:bg-slate-800/30'
                      }`}
                    >
                      {/* ID */}
                      <td className="py-3.5 px-4 font-bold text-cyan-400">
                        {corr.id}
                      </td>

                      {/* Time Window */}
                      <td className="py-3.5 px-4 text-slate-400 whitespace-nowrap">
                        <div className="text-slate-200">{corr.duration}</div>
                        <div className="text-[10px] text-slate-500">{corr.startTime.substring(11, 19)}</div>
                      </td>

                      {/* Agents */}
                      <td className="py-3.5 px-4">
                        <div className="flex items-center gap-1">
                          {corr.participatingAgents.map(ag => {
                            if (ag === 'NETWORK_AGENT') {
                              return (
                                <span key={ag} title="Network Agent" className="p-1 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                                  <Network className="w-3 h-3" />
                                </span>
                              );
                            }
                            if (ag === 'SYSTEM_AGENT') {
                              return (
                                <span key={ag} title="System Agent" className="p-1 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                                  <Cpu className="w-3 h-3" />
                                </span>
                              );
                            }
                            return (
                              <span key={ag} title="Application Agent" className="p-1 rounded bg-purple-950 text-purple-400 border border-purple-800">
                                <Globe className="w-3 h-3" />
                              </span>
                            );
                          })}
                        </div>
                      </td>

                      {/* Attack Pattern */}
                      <td className="py-3.5 px-4 font-sans font-medium text-slate-100 max-w-[220px] truncate">
                        {corr.title}
                      </td>

                      {/* Source */}
                      <td className="py-3.5 px-4 max-w-[140px] truncate text-slate-300">
                        {corr.sourceIps[0] || corr.sources[0] || 'Internal'}
                      </td>

                      {/* Target */}
                      <td className="py-3.5 px-4 max-w-[140px] truncate text-slate-300">
                        {corr.hosts[0] || corr.destinationIps[0] || 'Perimeter Gateway'}
                      </td>

                      {/* Strength */}
                      <td className="py-3.5 px-4">
                        <span className={`px-2 py-0.5 rounded font-bold text-[10px] ${
                          corr.correlationStrength === 'HIGH'
                            ? 'bg-rose-950 text-rose-300 border border-rose-800'
                            : corr.correlationStrength === 'MEDIUM'
                            ? 'bg-amber-950 text-amber-300 border border-amber-800'
                            : 'bg-slate-800 text-slate-300 border border-slate-700'
                        }`}>
                          {corr.correlationStrength}
                        </span>
                      </td>

                      {/* Confidence */}
                      <td className="py-3.5 px-4 text-emerald-400 font-bold">
                        {Math.round((corr.correlationConfidence || 0) * 100)}%
                      </td>

                      {/* Severity */}
                      <td className="py-3.5 px-4">
                        <SeverityBadge severity={corr.severity} />
                      </td>

                      {/* Status */}
                      <td className="py-3.5 px-4">
                        <StatusBadge status={corr.status} />
                      </td>

                      {/* Actions */}
                      <td className="py-3.5 px-4 text-right">
                        <div className="flex items-center justify-end gap-1.5" onClick={e => e.stopPropagation()}>
                          <button
                            id={`btn-inspect-${corr.id.toLowerCase()}`}
                            onClick={() => setModalEvent(corr)}
                            className="p-1 text-slate-400 hover:text-cyan-300 hover:bg-slate-800 rounded transition-colors"
                            title="Inspect Deep Forensic Breakdown"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>

                          {corr.status !== 'ESCALATED' && (
                            <button
                              id={`btn-escalate-${corr.id.toLowerCase()}`}
                              onClick={() => handleEscalate(corr.id)}
                              className="px-2 py-0.5 text-[10px] font-mono bg-slate-800 hover:bg-rose-900/60 hover:text-rose-200 text-slate-300 border border-slate-700 rounded transition-colors"
                            >
                              Escalate
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Deep Inspection Modal */}
      {modalEvent && (
        <CorrelationDetailModal
          event={modalEvent}
          onClose={() => setModalEvent(null)}
          onEscalate={handleEscalate}
        />
      )}
    </div>
  );
};
