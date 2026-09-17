import React, { useState, useEffect } from 'react';
import {
  Layers,
  AlertOctagon,
  Search,
  Filter,
  CheckCircle2,
  Clock,
  User,
  MessageSquare,
  Send,
  ShieldAlert,
  ChevronRight,
  RotateCcw,
  ExternalLink,
  Flame,
  FileText,
  Tag,
  Eye
} from 'lucide-react';
import { incidentManager } from '../../../services/alertIncident/incidentManager';
import { SecurityIncident, IncidentLifecycleStatus } from '../../../types/alertIncident';

export const IncidentManagementSection: React.FC = () => {
  const [incidents, setIncidents] = useState<SecurityIncident[]>(incidentManager.getIncidents());
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident | null>(null);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [newNoteText, setNewNoteText] = useState<string>('');

  useEffect(() => {
    const unsub = incidentManager.subscribe(() => {
      const all = incidentManager.getIncidents();
      setIncidents([...all]);
      if (selectedIncident) {
        const refreshed = all.find(i => (i.id || i.incidentId) === (selectedIncident.id || selectedIncident.incidentId));
        if (refreshed) setSelectedIncident(refreshed);
      }
    });

    const initAll = incidentManager.getIncidents();
    setIncidents(initAll);
    if (initAll.length > 0 && !selectedIncident) {
      setSelectedIncident(initAll[0]);
    }

    return () => unsub();
  }, []);

  const handleStatusChange = (newStatus: IncidentLifecycleStatus) => {
    if (!selectedIncident) return;
    const incId = selectedIncident.id || selectedIncident.incidentId;
    incidentManager.updateIncidentStatus(incId, newStatus, `Status transitioned to ${newStatus}`, 'SOC Analyst (Current User)');
  };

  const handleAddNote = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNoteText.trim() || !selectedIncident) return;
    const incId = selectedIncident.id || selectedIncident.incidentId;
    incidentManager.addAnalystNote(incId, newNoteText.trim(), 'SOC Analyst');
    setNewNoteText('');
  };

  // Severity color helper
  const getSeverityBadge = (sev: string) => {
    const s = (sev || '').toUpperCase();
    switch (s) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-300 border-rose-700';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-300 border-amber-700';
      case 'MEDIUM':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-700';
      default:
        return 'bg-blue-950/80 text-blue-300 border-blue-700';
    }
  };

  // Status badge helper
  const getStatusBadge = (status: string) => {
    const st = (status || '').toUpperCase();
    switch (st) {
      case 'RESOLVED':
        return 'bg-emerald-950/90 text-emerald-300 border-emerald-700';
      case 'INVESTIGATING':
        return 'bg-amber-950/90 text-amber-300 border-amber-700';
      case 'CONTAINED':
        return 'bg-indigo-950/90 text-indigo-300 border-indigo-700';
      case 'FALSE_POSITIVE':
        return 'bg-slate-800 text-slate-400 border-slate-700';
      case 'OPEN':
      case 'NEW':
      case 'ACKNOWLEDGED':
      default:
        return 'bg-rose-950/90 text-rose-300 border-rose-700';
    }
  };

  // Filtered incidents
  const filteredIncidents = incidents.filter(inc => {
    const incId = inc.id || inc.incidentId || '';
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      const match =
        incId.toLowerCase().includes(q) ||
        (inc.title || '').toLowerCase().includes(q) ||
        (inc.description || '').toLowerCase().includes(q) ||
        (inc.assignedTo || '').toLowerCase().includes(q);
      if (!match) return false;
    }
    if (statusFilter !== 'ALL') {
      const st = (inc.status || '').toUpperCase();
      if (statusFilter === 'OPEN' && st !== 'OPEN' && st !== 'NEW' && st !== 'ACKNOWLEDGED') return false;
      if (statusFilter === 'INVESTIGATING' && st !== 'INVESTIGATING') return false;
      if (statusFilter === 'RESOLVED' && st !== 'RESOLVED') return false;
    }
    if (severityFilter !== 'ALL' && inc.severity !== severityFilter) {
      return false;
    }
    return true;
  });

  return (
    <div className="space-y-6 font-mono" id="dashboard-section-incidents">
      {/* Top Banner */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xl">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-purple-400 animate-pulse" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-400" />
              Security Incident Management Center
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-700">
              {incidents.length} Active Dossiers
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Correlated multi-agent incident tracking, evidence compilation, status state machine, and analyst triage notes.
          </p>
        </div>

        {/* Quick Tally */}
        <div className="flex items-center gap-2 text-xs">
          <span className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-rose-300">
            Open: {incidents.filter(i => i.status !== 'RESOLVED' && i.status !== 'FALSE_POSITIVE').length}
          </span>
          <span className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-emerald-300">
            Resolved: {incidents.filter(i => i.status === 'RESOLVED').length}
          </span>
        </div>
      </div>

      {/* Filter and Search */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center gap-2 text-xs">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            placeholder="Search incident ID, title, or host..."
            className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-1">
          <span className="text-slate-500 text-[11px]">Status:</span>
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Statuses</option>
            <option value="OPEN">Open / New</option>
            <option value="INVESTIGATING">Investigating</option>
            <option value="RESOLVED">Resolved</option>
          </select>
        </div>

        <div className="flex items-center gap-1">
          <span className="text-slate-500 text-[11px]">Severity:</span>
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
          </select>
        </div>
      </div>

      {/* Master-Detail Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* Left: Incident List (5 cols) */}
        <div className="lg:col-span-5 space-y-2.5 max-h-[750px] overflow-y-auto pr-1">
          {filteredIncidents.length === 0 ? (
            <div className="p-8 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-xl">
              No incidents found.
            </div>
          ) : (
            filteredIncidents.map(inc => {
              const incId = inc.id || inc.incidentId || '';
              const isSelected = selectedIncident && (selectedIncident.id || selectedIncident.incidentId) === incId;

              return (
                <div
                  key={incId}
                  onClick={() => setSelectedIncident(inc)}
                  className={`p-4 rounded-xl border transition-all cursor-pointer shadow-lg ${
                    isSelected
                      ? 'bg-slate-850 border-purple-500/80 ring-1 ring-purple-500/30'
                      : 'bg-slate-900 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-white font-mono">{incId}</span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(inc.severity)}`}>
                        {inc.severity}
                      </span>
                    </div>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getStatusBadge(inc.status)}`}>
                      {inc.status}
                    </span>
                  </div>

                  <h4 className="text-xs font-bold text-slate-200 mt-2 line-clamp-1">
                    {inc.title || incId}
                  </h4>

                  <div className="mt-2.5 flex items-center justify-between text-[10px] text-slate-500 pt-2 border-t border-slate-800/80">
                    <span className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {inc.detectedAt || inc.createdAt || 'Recent'}
                    </span>
                    <span className="text-purple-400 font-semibold">
                      Risk Score: {inc.riskScore || 85}/100
                    </span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Right: Incident Details Panel (7 cols) */}
        <div className="lg:col-span-7">
          {selectedIncident ? (
            <div className="p-5 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-5">
              {/* Header Details */}
              <div>
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
                  <div className="flex items-center gap-2">
                    <AlertOctagon className="w-5 h-5 text-purple-400" />
                    <div>
                      <h3 className="text-sm font-bold text-white tracking-tight">
                        {selectedIncident.id || selectedIncident.incidentId}: {selectedIncident.title}
                      </h3>
                      <p className="text-[11px] text-slate-400 mt-0.5">
                        Detected: {selectedIncident.detectedAt || selectedIncident.createdAt || '2026-09-11 22:58:30'}
                      </p>
                    </div>
                  </div>

                  {/* Status Badges */}
                  <div className="flex items-center gap-2">
                    <span className={`px-2.5 py-1 rounded text-xs font-bold border ${getSeverityBadge(selectedIncident.severity)}`}>
                      {selectedIncident.severity}
                    </span>
                    <span className={`px-2.5 py-1 rounded text-xs font-bold border ${getStatusBadge(selectedIncident.status)}`}>
                      {selectedIncident.status}
                    </span>
                  </div>
                </div>

                {/* State Machine Action Buttons */}
                <div className="mt-3 p-3 bg-slate-950 rounded-lg border border-slate-800 flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs text-slate-400 font-semibold uppercase">
                    Transition Lifecycle Status:
                  </span>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    <button
                      onClick={() => handleStatusChange('NEW')}
                      disabled={selectedIncident.status === 'NEW'}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs border border-slate-700 disabled:opacity-40 transition-colors"
                    >
                      New
                    </button>
                    <button
                      onClick={() => handleStatusChange('INVESTIGATING')}
                      disabled={selectedIncident.status === 'INVESTIGATING'}
                      className="px-2.5 py-1 rounded bg-amber-950 hover:bg-amber-900 text-amber-300 text-xs border border-amber-800 disabled:opacity-40 transition-colors font-bold"
                    >
                      Investigating
                    </button>
                    <button
                      onClick={() => handleStatusChange('RESOLVED')}
                      disabled={selectedIncident.status === 'RESOLVED'}
                      className="px-2.5 py-1 rounded bg-emerald-950 hover:bg-emerald-900 text-emerald-300 text-xs border border-emerald-800 disabled:opacity-40 transition-colors font-bold"
                    >
                      Resolved
                    </button>
                  </div>
                </div>
              </div>

              {/* Description & Impact */}
              <div>
                <span className="text-[11px] text-slate-400 uppercase font-semibold block mb-1">
                  Incident Description & Impact
                </span>
                <p className="text-xs text-slate-300 leading-relaxed p-3 bg-slate-950 rounded-lg border border-slate-800">
                  {selectedIncident.description || 'Multi-source correlated threat sequence identified across perimeter and host surveillance agents.'}
                </p>
              </div>

              {/* Evidence & Related Events */}
              <div>
                <span className="text-[11px] text-slate-400 uppercase font-semibold block mb-1.5 flex items-center gap-1.5">
                  <FileText className="w-3.5 h-3.5 text-cyan-400" />
                  Evidence & Correlated Events
                </span>
                <div className="space-y-1.5">
                  {(selectedIncident.evidence && selectedIncident.evidence.length > 0) ? (
                    selectedIncident.evidence.map((item, idx) => (
                      <div key={idx} className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs text-slate-300 flex items-start gap-2">
                        <span className="text-purple-400 mt-0.5">▪</span>
                        <span>{typeof item === 'string' ? item : JSON.stringify(item)}</span>
                      </div>
                    ))
                  ) : (
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs text-slate-400">
                      Telemetry identifiers: {selectedIncident.alertIds?.join(', ') || 'ALT-1099, ALT-1098'}
                    </div>
                  )}
                </div>
              </div>

              {/* Analyst Notes */}
              <div>
                <span className="text-[11px] text-slate-400 uppercase font-semibold block mb-1.5 flex items-center gap-1.5">
                  <MessageSquare className="w-3.5 h-3.5 text-indigo-400" />
                  Analyst Investigation Notes
                </span>

                {/* Notes History */}
                <div className="space-y-2 max-h-48 overflow-y-auto mb-3 pr-1">
                  {(!selectedIncident.notes || selectedIncident.notes.length === 0) ? (
                    <p className="text-xs text-slate-500 italic p-2 bg-slate-950 rounded">
                      No investigation notes added yet.
                    </p>
                  ) : (
                    selectedIncident.notes.map((note, idx) => (
                      <div key={note.id || idx} className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs">
                        <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
                          <span className="text-slate-300 font-bold flex items-center gap-1">
                            <User className="w-3 h-3 text-cyan-400" />
                            {note.author}
                          </span>
                          <span>{note.timestamp}</span>
                        </div>
                        <p className="text-slate-300">{note.note}</p>
                      </div>
                    ))
                  )}
                </div>

                {/* Add Note Form */}
                <form onSubmit={handleAddNote} className="flex gap-2">
                  <input
                    type="text"
                    value={newNoteText}
                    onChange={e => setNewNoteText(e.target.value)}
                    placeholder="Add timestamped analyst note..."
                    className="flex-1 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs focus:outline-none focus:border-purple-500 font-mono"
                  />
                  <button
                    type="submit"
                    className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-bold transition-colors flex items-center gap-1"
                  >
                    <Send className="w-3 h-3" />
                    <span>Add Note</span>
                  </button>
                </form>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-slate-500 bg-slate-900 border border-slate-800 rounded-xl">
              Select an incident to view details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
