import React, { useState, useEffect } from 'react';
import { AlertOctagon, ShieldAlert, Eye, Search, Filter, Plus, Flame } from 'lucide-react';
import { Incident, IncidentStatus } from '../types';
import { incidentService } from '../services/incidentService';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';
import { IncidentDetailModal } from '../components/modals/IncidentDetailModal';

export const IncidentsPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  useEffect(() => {
    async function load() {
      const data = await incidentService.getIncidents();
      setIncidents(data);
    }
    load();
  }, []);

  const handleUpdateStatus = async (id: string, st: IncidentStatus) => {
    await incidentService.updateIncidentStatus(id, st);
    const refreshed = await incidentService.getIncidents();
    setIncidents(refreshed);
    const updated = refreshed.find(i => i.incidentId === id) || null;
    setSelectedIncident(updated);
  };

  const handleAssign = async (id: string, assignee: string) => {
    await incidentService.assignIncident(id, assignee);
    const refreshed = await incidentService.getIncidents();
    setIncidents(refreshed);
    const updated = refreshed.find(i => i.incidentId === id) || null;
    setSelectedIncident(updated);
  };

  const handleAddNote = async (id: string, note: string) => {
    await incidentService.addTimelineNote(id, note, 'SOC Analyst (Current User)');
    const refreshed = await incidentService.getIncidents();
    setIncidents(refreshed);
    const updated = refreshed.find(i => i.incidentId === id) || null;
    setSelectedIncident(updated);
  };

  const filteredIncidents = incidents.filter(inc => {
    const matchesSearch =
      inc.incidentId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.threatType.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.affectedSource.toLowerCase().includes(searchTerm.toLowerCase()) ||
      inc.assignedTo.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus =
      statusFilter === 'ALL' || inc.status === statusFilter;

    return matchesSearch && matchesStatus;
  });

  return (
    <div className="space-y-6" id="page-incidents">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest">
            SOC Incident Response Lifecycle
          </span>
        </div>
        <h2 className="text-xl font-bold text-white tracking-tight">
          Incident Management & Containment
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          Triage and investigate correlated security incidents. Track containment lifecycle status from New triage to Active Investigation, Network Isolation, and Final Post-Incident Resolution.
        </p>
      </div>

      {/* Incidents Table Controls */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
          <div className="relative flex-1 max-w-md">
            <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              id="input-search-incidents"
              type="text"
              placeholder="Search incident ID, threat type, asset, or assignee..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
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

        {/* 13. INCIDENTS TABLE */}
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
                <th className="py-3 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredIncidents.map(inc => (
                <tr
                  key={inc.incidentId}
                  id={`row-incident-${inc.incidentId.toLowerCase()}`}
                  className="hover:bg-slate-800/40 transition-colors"
                >
                  <td className="py-3 px-4 font-bold text-cyan-400">
                    {inc.incidentId}
                  </td>

                  <td className="py-3 px-4 text-slate-400">
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

                  <td className="py-3 px-4 text-right">
                    <button
                      id={`btn-open-incident-${inc.incidentId.toLowerCase()}`}
                      onClick={() => setSelectedIncident(inc)}
                      className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-cyan-400 rounded-lg border border-slate-700 transition-colors inline-flex items-center gap-1.5"
                    >
                      <Eye className="w-3.5 h-3.5" />
                      <span>Investigate</span>
                    </button>
                  </td>
                </tr>
              ))}
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
      />
    </div>
  );
};
