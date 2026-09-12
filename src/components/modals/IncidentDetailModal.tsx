import React, { useState } from 'react';
import { Incident, IncidentStatus } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import { X, ShieldAlert, CheckCircle2, User, Clock, AlertTriangle, Send } from 'lucide-react';

interface IncidentDetailModalProps {
  incident: Incident | null;
  onClose: () => void;
  onUpdateStatus: (incidentId: string, status: IncidentStatus) => void;
  onAssign: (incidentId: string, assignee: string) => void;
  onAddNote: (incidentId: string, note: string) => void;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  onClose,
  onUpdateStatus,
  onAssign,
  onAddNote
}) => {
  if (!incident) return null;

  const [newNote, setNewNote] = useState('');
  const [assigneeInput, setAssigneeInput] = useState(incident.assignedTo || '');

  const handleAddNoteSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newNote.trim()) return;
    onAddNote(incident.incidentId, newNote.trim());
    setNewNote('');
  };

  const handleAssignSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!assigneeInput.trim()) return;
    onAssign(incident.incidentId, assigneeInput.trim());
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div
        id="modal-incident-detail"
        className="bg-slate-900 border border-slate-700 rounded-2xl max-w-3xl w-full p-6 shadow-2xl space-y-6 my-8 text-slate-200"
      >
        {/* Header */}
        <div className="flex items-start justify-between pb-4 border-b border-slate-800">
          <div className="space-y-1">
            <div className="flex items-center gap-3">
              <span className="font-mono text-xs px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
                {incident.incidentId}
              </span>
              <SeverityBadge severity={incident.severity} size="md" />
              <StatusBadge status={incident.status} type="incident" />
            </div>
            <h2 className="text-xl font-bold text-white tracking-tight mt-2">
              {incident.threatType}
            </h2>
            <p className="text-xs text-slate-400 font-mono">
              Detected At: {incident.detectedAt} • Target Asset: {incident.affectedSource}
            </p>
          </div>
          <button
            id="btn-close-incident-modal"
            onClick={onClose}
            className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Quick Stats Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 font-mono">
            <div className="text-[11px] text-slate-400">Risk Score</div>
            <div className="text-xl font-bold text-rose-400">{incident.riskScore}/100</div>
          </div>
          <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 font-mono">
            <div className="text-[11px] text-slate-400">MITRE Tactic</div>
            <div className="text-xs font-semibold text-slate-200 truncate mt-1">{incident.mitreTactic}</div>
          </div>
          <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 font-mono">
            <div className="text-[11px] text-slate-400">Technique</div>
            <div className="text-xs font-semibold text-slate-200 truncate mt-1">{incident.mitreTechnique}</div>
          </div>
          <div className="p-3 bg-slate-950/80 rounded-xl border border-slate-800 font-mono">
            <div className="text-[11px] text-slate-400">Assigned To</div>
            <div className="text-xs font-semibold text-cyan-400 truncate mt-1">{incident.assignedTo}</div>
          </div>
        </div>

        {/* Status Transition Bar */}
        <div className="p-4 bg-slate-950/60 rounded-xl border border-slate-800/80 space-y-2">
          <label className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
            Incident Lifecycle Status Transition:
          </label>
          <div className="flex flex-wrap gap-2">
            {(['NEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'] as IncidentStatus[]).map(st => (
              <button
                key={st}
                id={`btn-set-status-${st.toLowerCase()}`}
                onClick={() => onUpdateStatus(incident.incidentId, st)}
                className={`px-3 py-1.5 rounded-lg text-xs font-mono font-medium border transition-all ${
                  incident.status === st
                    ? 'bg-cyan-950 text-cyan-300 border-cyan-600 shadow-[0_0_10px_rgba(6,182,212,0.2)]'
                    : 'bg-slate-900 text-slate-400 border-slate-800 hover:border-slate-700 hover:text-slate-200'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>

        {/* Summary & Containment */}
        <div className="space-y-4">
          <div>
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5">
              Incident Executive Summary
            </h4>
            <div className="p-3 bg-slate-950/90 rounded-lg border border-slate-800 text-xs leading-relaxed text-slate-300">
              {incident.summary}
            </div>
          </div>

          <div>
            <h4 className="text-xs font-mono uppercase tracking-wider text-amber-400 mb-1.5 flex items-center gap-1.5">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              Containment & Remediation Recommendation
            </h4>
            <div className="p-3 bg-amber-950/20 border border-amber-800/40 rounded-lg text-xs leading-relaxed text-amber-200 font-mono">
              {incident.containmentRecommendation}
            </div>
          </div>
        </div>

        {/* Timeline & Notes */}
        <div className="space-y-3">
          <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <Clock className="w-4 h-4 text-cyan-400" />
            Detection & Response Timeline
          </h4>
          <div className="max-h-48 overflow-y-auto space-y-2 pr-2">
            {incident.timeline.map((entry, idx) => (
              <div
                key={idx}
                className="flex items-start gap-3 p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80 text-xs font-mono"
              >
                <span className="text-slate-500 shrink-0 text-[11px] pt-0.5">{entry.time}</span>
                <div className="flex-1">
                  <p className="text-slate-200">{entry.description}</p>
                  <span className="text-[10px] text-cyan-400">Actor: {entry.actor}</span>
                </div>
              </div>
            ))}
          </div>

          {/* Add note form */}
          <form onSubmit={handleAddNoteSubmit} className="flex gap-2 pt-2">
            <input
              type="text"
              placeholder="Add investigator note or forensic artifact..."
              value={newNote}
              onChange={e => setNewNote(e.target.value)}
              className="flex-1 px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
            <button
              type="submit"
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-mono inline-flex items-center gap-1.5 transition-colors"
            >
              <Send className="w-3.5 h-3.5" />
              <span>Post</span>
            </button>
          </form>
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between pt-4 border-t border-slate-800">
          <form onSubmit={handleAssignSubmit} className="flex items-center gap-2">
            <User className="w-4 h-4 text-slate-400" />
            <input
              type="text"
              value={assigneeInput}
              onChange={e => setAssigneeInput(e.target.value)}
              placeholder="Assign SOC analyst..."
              className="px-2.5 py-1 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 font-mono focus:border-cyan-500 focus:outline-none"
            />
            <button
              type="submit"
              className="px-2.5 py-1 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-colors"
            >
              Reassign
            </button>
          </form>

          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-colors"
          >
            Close Incident
          </button>
        </div>
      </div>
    </div>
  );
};
