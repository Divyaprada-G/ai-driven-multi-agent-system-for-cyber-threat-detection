/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 9: Alert Management Center
 */

import React, { useState, useEffect } from 'react';
import {
  Bell,
  Search,
  Filter,
  ShieldAlert,
  AlertTriangle,
  Sliders,
  Play,
  Download,
  CheckCircle2,
  ExternalLink,
  Layers,
  Flame,
  Clock,
  Eye,
  Terminal,
  Activity
} from 'lucide-react';
import { SecurityAlert, AlertLifecycleStatus } from '../types/alertIncident';
import { alertManager } from '../services/alertIncident/alertManager';
import { incidentManager } from '../services/alertIncident/incidentManager';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { AlertDetailModal } from '../components/alerts/AlertDetailModal';
import { AlertGenerationRulesModal } from '../components/alerts/AlertGenerationRulesModal';
import { AlertsVerificationModal } from '../components/alerts/AlertsVerificationModal';
import { SimulateResponseModal } from '../components/alerts/SimulateResponseModal';
import { NavPageId } from '../components/layout/Sidebar';

interface AlertsPageProps {
  onNavigate?: (page: NavPageId) => void;
  onNavigateToIncident?: (incidentId: string) => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({
  onNavigate,
  onNavigateToIncident
}) => {
  const [alerts, setAlerts] = useState<SecurityAlert[]>(alertManager.getAlerts());
  const [selectedAlert, setSelectedAlert] = useState<SecurityAlert | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [priorityFilter, setPriorityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [agentFilter, setAgentFilter] = useState('ALL');

  // Modal controls
  const [isRulesModalOpen, setIsRulesModalOpen] = useState(false);
  const [isVerifyModalOpen, setIsVerifyModalOpen] = useState(false);
  const [simulateTargetAlert, setSimulateTargetAlert] = useState<SecurityAlert | null>(null);

  // Multi-select for incident grouping
  const [selectedAlertIds, setSelectedAlertIds] = useState<string[]>([]);
  const [isGrouping, setIsGrouping] = useState(false);
  const [scenarioRunning, setScenarioRunning] = useState(false);
  const [scenarioMessage, setScenarioMessage] = useState<string | null>(null);

  useEffect(() => {
    alertManager.syncWithBackend();
    const update = () => {
      setAlerts(alertManager.getAlerts());
    };
    return alertManager.subscribe(update);
  }, []);

  const handleUpdateStatus = (id: string, newStatus: AlertLifecycleStatus) => {
    alertManager.updateAlertStatus(id, newStatus);
    const updated = alertManager.getAlertById(id) || null;
    setSelectedAlert(updated);
  };

  const handleSelectAll = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.checked) {
      setSelectedAlertIds(filteredAlerts.map(a => a.id));
    } else {
      setSelectedAlertIds([]);
    }
  };

  const handleToggleSelectAlert = (id: string) => {
    if (selectedAlertIds.includes(id)) {
      setSelectedAlertIds(selectedAlertIds.filter(i => i !== id));
    } else {
      setSelectedAlertIds([...selectedAlertIds, id]);
    }
  };

  const handleGroupSelectedIntoIncident = () => {
    if (selectedAlertIds.length === 0) return;
    setIsGrouping(true);
    const newInc = incidentManager.groupAlertsIntoIncident(
      selectedAlertIds,
      undefined,
      `Correlated Incident (${selectedAlertIds.length} Alerts)`,
      `Grouped from analyst triage of ${selectedAlertIds.length} alert events.`
    );
    setSelectedAlertIds([]);
    setIsGrouping(false);
    if (newInc && onNavigateToIncident) {
      onNavigateToIncident(newInc.id);
    } else if (onNavigate) {
      onNavigate('incidents');
    }
  };

  // Run Safe Multi-Stage Intrusion Demo Scenario
  const handleRunSimulatedScenario = () => {
    setScenarioRunning(true);
    setScenarioMessage('Injecting simulated multi-stage attack stream across agents...');

    setTimeout(() => {
      // Create simulated risk assessment with high multi-agent severity
      const scenarioAssessment = {
        id: `RISK-SCENARIO-${Date.now()}`,
        threatDetectionId: `THREAT-SCENARIO-${Date.now()}`,
        correlationId: `CORR-SCENARIO-${Date.now()}`,
        timestamp: new Date().toLocaleTimeString(),
        riskScore: 94,
        severity: 'CRITICAL' as const,
        priority: 'P1' as const,
        riskBand: 'CRITICAL' as const,
        confidence: 97,
        riskFactors: [],
        threatClassification: 'Coordinated Multi-Stage APT Intrusion',
        explanation: 'Simulated multi-stage attack correlating perimeter scan, web query SQLi, and endpoint privilege escalation.',
        recommendedAction: 'Isolate host workstation-exec-01 and enforce egress WAF rate-limiting.',
        status: 'NEW' as const,
        participatingAgents: ['NETWORK_AGENT' as const, 'APPLICATION_AGENT' as const, 'SYSTEM_AGENT' as const],
        evidenceVolume: 12,
        affectedEntitiesCount: 3,
        affectedSource: 'workstation-exec-01',
        auditTrail: {
          calculatedAt: new Date().toLocaleTimeString(),
          modelUsed: 'Stage-9-Demo-Simulator',
          correlationStrength: 0.96,
          mlAnomalyScore: 0.94,
          weightsConfigVersion: '1.0'
        },
        score: 94,
        remediationPlan: ['Quarantine workstation', 'Revoke credentials']
      };

      const result = alertManager.processRiskAssessment(scenarioAssessment);
      setScenarioRunning(false);
      setScenarioMessage(
        result.alert
          ? `Scenario Injected! Generated new P1 Alert [${result.alert.id}].`
          : 'Scenario processed.'
      );

      setTimeout(() => setScenarioMessage(null), 5000);
    }, 800);
  };

  // Export alerts to JSON
  const handleExportJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(alerts, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `soc_alerts_export_${new Date().toISOString().split('T')[0]}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Filter logic
  const filteredAlerts = alerts.filter(alert => {
    const matchesSearch =
      alert.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
      String(alert.threatClassification).toLowerCase().includes(searchTerm.toLowerCase()) ||
      alert.explanation.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity = severityFilter === 'ALL' || alert.severity === severityFilter;
    const matchesPriority = priorityFilter === 'ALL' || alert.priority === priorityFilter;
    const matchesStatus = statusFilter === 'ALL' || alert.status === statusFilter;
    const matchesAgent =
      agentFilter === 'ALL' ||
      alert.participatingAgents.some(ag => ag === agentFilter);

    return matchesSearch && matchesSeverity && matchesPriority && matchesStatus && matchesAgent;
  });

  // KPI calculations
  const totalAlerts = alerts.length;
  const newAlerts = alerts.filter(a => a.status === 'NEW').length;
  const p1Count = alerts.filter(a => a.priority === 'P1').length;
  const p2Count = alerts.filter(a => a.priority === 'P2').length;
  const p3Count = alerts.filter(a => a.priority === 'P3').length;
  const p4Count = alerts.filter(a => a.priority === 'P4').length;
  const deduplicatedTotal = alerts.reduce((acc, a) => acc + (a.deduplicationCount - 1), 0);

  return (
    <div className="space-y-6" id="page-alerts">
      {/* Top Banner Notice: Architecture Overview */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 border border-slate-800 rounded-xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-xs font-mono uppercase tracking-widest text-cyan-400 font-semibold">
              Stage 9 • Alert & Incident Management
            </span>
            <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800">
              DEMO / SIMULATED DATA
            </span>
          </div>
          <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">
            Security Alert Operations & Triage
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Real-time alert generation from explainable risk scores, burst deduplication, lifecycle triage, and prepared n8n integration payloads.
          </p>
        </div>

        {/* Global Alert Action Buttons */}
        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <button
            id="btn-alert-run-scenario"
            onClick={handleRunSimulatedScenario}
            disabled={scenarioRunning}
            className="px-3 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-semibold transition-colors flex items-center gap-1.5 shadow-lg shadow-cyan-600/20 disabled:opacity-50"
          >
            <Play className={`w-3.5 h-3.5 ${scenarioRunning ? 'animate-spin' : ''}`} />
            <span>{scenarioRunning ? 'Injecting...' : 'Run Attack Scenario Demo'}</span>
          </button>

          <button
            id="btn-alert-rules"
            onClick={() => setIsRulesModalOpen(true)}
            className="px-3 py-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700 font-semibold transition-colors flex items-center gap-1.5"
          >
            <Sliders className="w-3.5 h-3.5 text-cyan-400" />
            <span>Alert Rules</span>
          </button>

          <button
            id="btn-alert-verify-tests"
            onClick={() => setIsVerifyModalOpen(true)}
            className="px-3 py-2 rounded-lg bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-700/60 font-semibold transition-colors flex items-center gap-1.5"
          >
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span>Verify (14 Tests)</span>
          </button>

          <button
            id="btn-alert-export"
            onClick={handleExportJSON}
            className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition-colors"
            title="Export Alerts JSON"
          >
            <Download className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Scenario Notification Banner */}
      {scenarioMessage && (
        <div className="p-3 bg-cyan-950/60 border border-cyan-500/60 rounded-xl text-xs font-mono text-cyan-200 flex items-center gap-2">
          <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
          <span>{scenarioMessage}</span>
        </div>
      )}

      {/* KPI Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-3">
        <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl font-mono">
          <div className="text-[11px] text-slate-400">Total Alerts</div>
          <div className="text-xl font-bold text-white mt-1">{totalAlerts}</div>
        </div>

        <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl font-mono">
          <div className="text-[11px] text-cyan-400 flex items-center justify-between">
            <span>New Triage</span>
            {newAlerts > 0 && <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />}
          </div>
          <div className="text-xl font-bold text-cyan-300 mt-1">{newAlerts}</div>
        </div>

        <div className="p-3.5 bg-rose-950/30 border border-rose-800/40 rounded-xl font-mono">
          <div className="text-[11px] text-rose-400">P1 Critical</div>
          <div className="text-xl font-bold text-rose-300 mt-1">{p1Count}</div>
        </div>

        <div className="p-3.5 bg-orange-950/30 border border-orange-800/40 rounded-xl font-mono">
          <div className="text-[11px] text-orange-400">P2 High</div>
          <div className="text-xl font-bold text-orange-300 mt-1">{p2Count}</div>
        </div>

        <div className="p-3.5 bg-amber-950/30 border border-amber-800/40 rounded-xl font-mono">
          <div className="text-[11px] text-amber-400">P3 Medium</div>
          <div className="text-xl font-bold text-amber-300 mt-1">{p3Count}</div>
        </div>

        <div className="p-3.5 bg-blue-950/30 border border-blue-800/40 rounded-xl font-mono">
          <div className="text-[11px] text-blue-400">P4 Low</div>
          <div className="text-xl font-bold text-blue-300 mt-1">{p4Count}</div>
        </div>

        <div className="p-3.5 bg-purple-950/30 border border-purple-800/40 rounded-xl font-mono col-span-2 sm:col-span-1">
          <div className="text-[11px] text-purple-400">Deduplicated</div>
          <div className="text-xl font-bold text-purple-300 mt-1">+{deduplicatedTotal}</div>
        </div>
      </div>

      {/* Bulk Action Bar (when alerts selected) */}
      {selectedAlertIds.length > 0 && (
        <div className="p-3 bg-cyan-950/70 border border-cyan-500/60 rounded-xl flex items-center justify-between font-mono text-xs text-slate-200 shadow-lg">
          <div className="flex items-center gap-2">
            <span className="font-bold text-cyan-300">{selectedAlertIds.length}</span>
            <span>alerts selected</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleGroupSelectedIntoIncident}
              disabled={isGrouping}
              className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-lg transition-colors flex items-center gap-1.5"
            >
              <Layers className="w-3.5 h-3.5" />
              <span>Group into Security Incident &rarr;</span>
            </button>
            <button
              onClick={() => {
                selectedAlertIds.forEach(id => alertManager.updateAlertStatus(id, 'ACKNOWLEDGED'));
                setSelectedAlertIds([]);
              }}
              className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700"
            >
              Acknowledge All
            </button>
            <button
              onClick={() => setSelectedAlertIds([])}
              className="px-2 py-1.5 text-slate-400 hover:text-white"
            >
              Deselect
            </button>
          </div>
        </div>
      )}

      {/* Alerts Table Controls */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-col lg:flex-row gap-3 lg:items-center lg:justify-between">
          {/* Search Bar */}
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              id="input-search-alerts"
              type="text"
              placeholder="Search alert ID, threat, asset, or explanation..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          {/* Filters Bar */}
          <div className="flex flex-wrap items-center gap-2">
            {/* Severity Filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-slate-400 font-mono">Severity:</span>
              <select
                id="select-alert-severity-filter"
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                className="text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            {/* Priority Filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-slate-400 font-mono">Priority:</span>
              <select
                id="select-alert-priority-filter"
                value={priorityFilter}
                onChange={e => setPriorityFilter(e.target.value)}
                className="text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Priorities</option>
                <option value="P1">P1 (Critical)</option>
                <option value="P2">P2 (High)</option>
                <option value="P3">P3 (Medium)</option>
                <option value="P4">P4 (Low)</option>
              </select>
            </div>

            {/* Status Filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-slate-400 font-mono">Status:</span>
              <select
                id="select-alert-status-filter"
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                className="text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="NEW">New</option>
                <option value="ACKNOWLEDGED">Acknowledged</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="RESOLVED">Resolved</option>
                <option value="FALSE_POSITIVE">False Positive</option>
              </select>
            </div>

            {/* Agent Filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-slate-400 font-mono">Agent:</span>
              <select
                id="select-alert-agent-filter"
                value={agentFilter}
                onChange={e => setAgentFilter(e.target.value)}
                className="text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1 text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Agents</option>
                <option value="NETWORK_AGENT">Network</option>
                <option value="SYSTEM_AGENT">System</option>
                <option value="APPLICATION_AGENT">Application</option>
              </select>
            </div>
          </div>
        </div>

        {/* Alerts Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-3 w-8">
                  <input
                    type="checkbox"
                    checked={filteredAlerts.length > 0 && selectedAlertIds.length === filteredAlerts.length}
                    onChange={handleSelectAll}
                    className="w-3.5 h-3.5 rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
                  />
                </th>
                <th className="py-3 px-3">Priority</th>
                <th className="py-3 px-4">Alert ID</th>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Threat Title</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Source Asset</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Incident</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredAlerts.length === 0 ? (
                <tr>
                  <td colSpan={11} className="py-8 text-center text-slate-500">
                    No security alerts found matching current filter criteria.
                  </td>
                </tr>
              ) : (
                filteredAlerts.map(alert => {
                  const priorityColor =
                    alert.priority === 'P1'
                      ? 'text-rose-400 bg-rose-950/70 border-rose-800'
                      : alert.priority === 'P2'
                      ? 'text-orange-400 bg-orange-950/70 border-orange-800'
                      : alert.priority === 'P3'
                      ? 'text-amber-400 bg-amber-950/70 border-amber-800'
                      : 'text-blue-400 bg-blue-950/70 border-blue-800';

                  const isSelected = selectedAlertIds.includes(alert.id);

                  return (
                    <tr
                      key={alert.id}
                      id={`row-alert-${alert.id.toLowerCase()}`}
                      className={`hover:bg-slate-800/40 transition-colors ${
                        !alert.isRead ? 'bg-slate-900/30 font-semibold' : ''
                      } ${isSelected ? 'bg-cyan-950/30' : ''}`}
                    >
                      <td className="py-3 px-3">
                        <input
                          type="checkbox"
                          checked={isSelected}
                          onChange={() => handleToggleSelectAlert(alert.id)}
                          className="w-3.5 h-3.5 rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0"
                        />
                      </td>

                      <td className="py-3 px-3">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${priorityColor}`}>
                          {alert.priority}
                        </span>
                      </td>

                      <td className="py-3 px-4 text-cyan-400 font-bold whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          {!alert.isRead && <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />}
                          <span>{alert.id}</span>
                        </div>
                      </td>

                      <td className="py-3 px-4 text-slate-400 whitespace-nowrap text-[11px]">
                        <div>{alert.timestamp.includes(' ') ? alert.timestamp.split(' ')[1] : alert.timestamp}</div>
                        {alert.deduplicationCount > 1 && (
                          <div className="text-[9px] text-purple-400">&times;{alert.deduplicationCount} burst</div>
                        )}
                      </td>

                      <td className="py-3 px-4 max-w-[240px]">
                        <div className="font-sans font-medium text-slate-100 truncate">
                          {alert.title}
                        </div>
                        <div className="text-[10px] text-slate-400 truncate">
                          {alert.threatClassification}
                        </div>
                      </td>

                      <td className="py-3 px-4">
                        <SeverityBadge severity={alert.severity} />
                      </td>

                      <td className="py-3 px-4 font-bold text-rose-400">
                        {alert.riskScore}/100
                      </td>

                      <td className="py-3 px-4 text-slate-300 max-w-[160px] truncate text-[11px]">
                        {alert.source}
                      </td>

                      <td className="py-3 px-4">
                        <StatusBadge status={alert.status} type="alert" />
                      </td>

                      <td className="py-3 px-4 text-[11px]">
                        {alert.incidentId ? (
                          <button
                            onClick={() => {
                              if (onNavigateToIncident && alert.incidentId) {
                                onNavigateToIncident(alert.incidentId);
                              }
                            }}
                            className="text-cyan-400 hover:text-cyan-300 underline font-bold"
                          >
                            {alert.incidentId}
                          </button>
                        ) : (
                          <span className="text-slate-600">-</span>
                        )}
                      </td>

                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-1.5">
                          {alert.status === 'NEW' && (
                            <button
                              id={`btn-ack-alert-${alert.id.toLowerCase()}`}
                              onClick={() => handleUpdateStatus(alert.id, 'ACKNOWLEDGED')}
                              className="px-2 py-1 bg-slate-800 hover:bg-cyan-900/60 text-cyan-300 rounded border border-slate-700 text-[11px] transition-colors"
                              title="Acknowledge Alert"
                            >
                              Ack
                            </button>
                          )}

                          <button
                            id={`btn-open-alert-${alert.id.toLowerCase()}`}
                            onClick={() => {
                              alertManager.markAsRead(alert.id);
                              setSelectedAlert(alert);
                            }}
                            className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded border border-slate-700 text-[11px] transition-colors inline-flex items-center gap-1"
                          >
                            <Eye className="w-3 h-3 text-cyan-400" />
                            <span>Details</span>
                          </button>

                          <button
                            id={`btn-simulate-alert-${alert.id.toLowerCase()}`}
                            onClick={() => setSimulateTargetAlert(alert)}
                            className="px-2 py-1 bg-amber-950/60 hover:bg-amber-900 text-amber-300 rounded border border-amber-800 text-[11px] transition-colors"
                            title="Simulate Response"
                          >
                            <Terminal className="w-3 h-3" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alert Detail Modal */}
      <AlertDetailModal
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onStatusUpdated={handleUpdateStatus}
        onNavigateToIncident={onNavigateToIncident}
      />

      {/* Alert Generation Rules Policy Modal */}
      <AlertGenerationRulesModal
        isOpen={isRulesModalOpen}
        onClose={() => setIsRulesModalOpen(false)}
      />

      {/* 14 Verification Tests Modal */}
      <AlertsVerificationModal
        isOpen={isVerifyModalOpen}
        onClose={() => setIsVerifyModalOpen(false)}
      />

      {/* Standalone Response Simulation Modal */}
      {simulateTargetAlert && (
        <SimulateResponseModal
          isOpen={Boolean(simulateTargetAlert)}
          onClose={() => setSimulateTargetAlert(null)}
          targetId={simulateTargetAlert.id}
          targetType="ALERT"
          defaultTargetEntity={simulateTargetAlert.source}
        />
      )}
    </div>
  );
};
