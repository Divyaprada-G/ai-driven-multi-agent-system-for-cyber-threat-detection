import React, { useState, useEffect } from 'react';
import {
  AlertOctagon,
  ShieldAlert,
  Eye,
  Search,
  Filter,
  Layers,
  Clock,
  CheckCircle2,
  Terminal,
  ExternalLink
} from 'lucide-react';
import { Incident, IncidentStatus } from '../types';
import { incidentManager } from '../services/alertIncident/incidentManager';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { IncidentDetailModal } from '../components/modals/IncidentDetailModal';
import { SimulateResponseModal } from '../components/alerts/SimulateResponseModal';

interface IncidentsPageProps {
  initialIncidentId?: string;
  onNavigateToAlert?: (alertId: string) => void;
}

export const IncidentsPage: React.FC<IncidentsPageProps> = ({
  initialIncidentId,
  onNavigateToAlert
}) => {
  const [incidents, setIncidents] = useState<Incident[]>(incidentManager.getIncidents());
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [simulateTargetIncident, setSimulateTargetIncident] = useState<Incident | null>(null);

  useEffect(() => {
    incidentManager.syncWithBackend();
    const update = () => {
      const current = incidentManager.getIncidents();
      setIncidents(current);
      if (selectedIncident) {
        const refreshed = incidentManager.getIncidentById(selectedIncident.incidentId);
        if (refreshed) setSelectedIncident(refreshed);
      }
    };
    return incidentManager.subscribe(update);
  }, [selectedIncident]);

  useEffect(() => {
    if (initialIncidentId) {
      const inc = incidentManager.getIncidentById(initialIncidentId);
      if (inc) setSelectedIncident(inc);
    }
  }, [initialIncidentId]);

  const handleUpdateStatus = (id: string, st: IncidentStatus) => {
    incidentManager.updateIncidentStatus(id, st);
    const updated = incidentManager.getIncidentById(id) || null;
    setSelectedIncident(updated);
  };

  const handleAssign = (id: string, assignee: string) => {
    incidentManager.assignIncident(id, assignee);
    const updated = incidentManager.getIncidentById(id) || null;
    setSelectedIncident(updated);
  };

  const handleAddNote = (id: string, note: string) => {
    incidentManager.addAnalystNote(id, note, 'SOC Analyst (Active Session)');
    const updated = incidentManager.getIncidentById(id) || null;
    setSelectedIncident(updated);
  };

  const filteredIncidents = incidents.filter(inc => {
    const matchesSearch =
      inc.incidentId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.threatType.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.affectedSource.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.assignedTo.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.summary.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus = statusFilter === 'ALL' || inc.status === statusFilter;
    const matchesSeverity = severityFilter === 'ALL' || inc.severity === severityFilter;

    return matchesSearch && matchesStatus && matchesSeverity;
  });

  const totalIncidents = incidents.length;
  const newCount = incidents.filter(i => i.status === 'NEW').length;
  const investigatingCount = incidents.filter(i => i.status === 'INVESTIGATING').length;
  const containedCount = incidents.filter(i => i.status === 'CONTAINED').length;
  const resolvedCount = incidents.filter(i => i.status === 'RESOLVED').length;

  return (
    <div className="space-y-6" id="page-incidents">
      {/* Header Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 border border-slate-800 rounded-xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-xs font-mono uppercase tracking-widest text-cyan-400 font-semibold">
              Stage 9 • Correlated Incident Dossiers
            </span>
            <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-amber-950 text-amber-300 border border-amber-800">
              DEMO / SIMULATED DATA
            </span>
          </div>
          <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">
            Security Incident Dossiers & Containment
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Correlated threat grouping linking security alerts, causal explanations, MITRE ATT&CK techniques, timeline logs, and safe response containment simulations.
          </p>
        </div>
      </div>

      {/* Incident Status Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl font-mono">
          <div className="text-[11px] text-slate-400">Total Incidents</div>
          <div className="text-xl font-bold text-white mt-1">{totalIncidents}</div>
        </div>

        <div className="p-3.5 bg-slate-900/80 border border-slate-800 rounded-xl font-mono">
          <div className="text-[11px] text-cyan-400 flex items-center justify-between">
            <span>New Triage</span>
            {newCount > 0 && <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />}
          </div>
          <div className="text-xl font-bold text-cyan-300 mt-1">{newCount}</div>
        </div>

        <div className="p-3.5 bg-amber-950/30 border border-amber-800/40 rounded-xl font-mono">
          <div className="text-[11px] text-amber-400">Investigating</div>
          <div className="text-xl font-bold text-amber-300 mt-1">{investigatingCount}</div>
        </div>

        <div className="p-3.5 bg-purple-950/30 border border-purple-800/40 rounded-xl font-mono">
          <div className="text-[11px] text-purple-400">Contained</div>
          <div className="text-xl font-bold text-purple-300 mt-1">{containedCount}</div>
        </div>

        <div className="p-3.5 bg-emerald-950/30 border border-emerald-800/40 rounded-xl font-mono col-span-2 sm:col-span-1">
          <div className="text-[11px] text-emerald-400">Resolved</div>
          <div className="text-xl font-bold text-emerald-300 mt-1">{resolvedCount}</div>
        </div>
      </div>

      {/* Incidents Table Controls */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              id="input-search-incidents"
              type="text"
              placeholder="Search incident ID, threat type, asset, or summary..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-slate-400 font-mono">Severity:</span>
              <select
                id="select-incident-severity-filter"
                value={severityFilter}
                onChange={e => setSeverityFilter(e.target.value)}
                className="text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </div>

            <div className="flex items-center gap-1.5">
              <span className="text-xs text-slate-400 font-mono">Status:</span>
              <select
                id="select-incident-status-filter"
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                className="text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="NEW">New</option>
                <option value="INVESTIGATING">Investigating</option>
                <option value="CONTAINED">Contained</option>
                <option value="RESOLVED">Resolved</option>
              </select>
            </div>
          </div>
        </div>

        {/* Incidents Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Incident ID</th>
                <th className="py-3 px-4">Detected At</th>
                <th className="py-3 px-4">Threat Type</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Affected Source</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Assigned To</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-8 text-center text-slate-500">
                    No security incidents found matching current filters.
                  </td>
                </tr>
              ) : (
                filteredIncidents.map(inc => (
                  <tr
                    key={inc.incidentId}
                    id={`row-incident-${inc.incidentId.toLowerCase()}`}
                    className="hover:bg-slate-800/40 transition-colors"
                  >
                    <td className="py-3 px-4 font-bold text-cyan-400 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        <span>{inc.incidentId}</span>
                        {inc.alertIds && inc.alertIds.length > 0 && (
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                            {inc.alertIds.length}a
                          </span>
                        )}
                      </div>
                    </td>

                    <td className="py-3 px-4 text-slate-400 whitespace-nowrap text-[11px]">
                      {inc.detectedAt}
                    </td>

                    <td className="py-3 px-4 font-sans font-medium text-slate-100 max-w-[220px] truncate">
                      {inc.threatType}
                    </td>

                    <td className="py-3 px-4">
                      <SeverityBadge severity={inc.severity} />
                    </td>

                    <td className="py-3 px-4 font-bold text-rose-400">
                      {inc.riskScore}/100
                    </td>

                    <td className="py-3 px-4 text-slate-300 max-w-[180px] truncate">
                      {inc.affectedSource}
                    </td>

                    <td className="py-3 px-4">
                      <StatusBadge status={inc.status} type="incident" />
                    </td>

                    <td className="py-3 px-4 text-slate-200">
                      {inc.assignedTo}
                    </td>

                    <td className="py-3 px-4 text-right whitespace-nowrap">
                      <div className="flex items-center justify-end gap-1.5">
                        <button
                          id={`btn-open-incident-${inc.incidentId.toLowerCase()}`}
                          onClick={() => setSelectedIncident(inc)}
                          className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded-lg border border-slate-700 transition-colors inline-flex items-center gap-1.5"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>Investigate</span>
                        </button>

                        <button
                          id={`btn-simulate-incident-${inc.incidentId.toLowerCase()}`}
                          onClick={() => setSimulateTargetIncident(inc)}
                          className="px-2 py-1 bg-amber-950/60 hover:bg-amber-900 text-amber-300 rounded border border-amber-800 text-[11px] transition-colors"
                          title="Simulate Containment Action"
                        >
                          <Terminal className="w-3 h-3" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Incident Detail Modal */}
      <IncidentDetailModal
        incident={selectedIncident}
        onClose={() => setSelectedIncident(null)}
        onUpdateStatus={handleUpdateStatus}
        onAssign={handleAssign}
        onAddNote={handleAddNote}
        onSelectAlert={onNavigateToAlert}
      />

      {/* Standalone Containment Simulation Modal */}
      {simulateTargetIncident && (
        <SimulateResponseModal
          isOpen={Boolean(simulateTargetIncident)}
          onClose={() => setSimulateTargetIncident(null)}
          targetId={simulateTargetIncident.incidentId}
          targetType="INCIDENT"
          defaultTargetEntity={simulateTargetIncident.affectedSource}
        />
      )}
    </div>
  );
};
