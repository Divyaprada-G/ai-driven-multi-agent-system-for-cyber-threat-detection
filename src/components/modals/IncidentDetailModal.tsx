import React, { useState } from 'react';
import { Incident, IncidentStatus } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import {
  X,
  ShieldAlert,
  CheckCircle2,
  User,
  Clock,
  AlertTriangle,
  Send,
  Terminal,
  Layers,
  ArrowRight,
  ExternalLink,
  Lock,
  WifiOff,
  GitMerge
} from 'lucide-react';
import { incidentManager } from '../../services/alertIncident/incidentManager';
import { SimulateResponseModal } from '../alerts/SimulateResponseModal';

interface IncidentDetailModalProps {
  incident: Incident | null;
  onClose: () => void;
  onUpdateStatus: (incidentId: string, status: IncidentStatus) => void;
  onAssign: (incidentId: string, assignee: string) => void;
  onAddNote: (incidentId: string, note: string) => void;
  onSelectAlert?: (alertId: string) => void;
}

export const IncidentDetailModal: React.FC<IncidentDetailModalProps> = ({
  incident,
  onClose,
  onUpdateStatus,
  onAssign,
  onAddNote,
  onSelectAlert
}) => {
  if (!incident) return null;

  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'TIMELINE' | 'ALERTS' | 'TRACEABILITY'>('OVERVIEW');
  const [newNote, setNewNote] = useState('');
  const [assigneeInput, setAssigneeInput] = useState(incident.assignedTo || '');
  const [isSimulateModalOpen, setIsSimulateModalOpen] = useState(false);

  // Retrieve end-to-end traceability chain
  const firstAlertId = incident.alertIds && incident.alertIds.length > 0 ? incident.alertIds[0] : undefined;
  const traceChain = firstAlertId ? incidentManager.getTraceabilityChain(firstAlertId) : null;

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
    <>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm overflow-y-auto">
        <div
          id="modal-incident-detail"
          className="bg-slate-900 border border-slate-700 rounded-2xl max-w-4xl w-full p-6 shadow-2xl space-y-5 my-8 text-slate-200"
        >
          {/* Header */}
          <div className="flex items-start justify-between pb-4 border-b border-slate-800">
            <div className="space-y-1.5 max-w-2xl">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs px-2.5 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 font-bold">
                  {incident.incidentId}
                </span>
                <SeverityBadge severity={incident.severity} size="md" />
                <StatusBadge status={incident.status} type="incident" />
                {incident.alertIds && incident.alertIds.length > 0 && (
                  <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
                    {incident.alertIds.length} Linked Alerts
                  </span>
                )}
              </div>
              <h2 className="text-xl font-bold text-white tracking-tight">
                {incident.threatType}
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Detected: {incident.detectedAt} • Target Asset: {incident.affectedSource}
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
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
              <div className="text-[11px] text-slate-400">Aggregated Risk</div>
              <div className="text-xl font-bold text-rose-400 mt-0.5">{incident.riskScore}/100</div>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
              <div className="text-[11px] text-slate-400">MITRE Tactic</div>
              <div className="text-xs font-semibold text-slate-200 truncate mt-1">{incident.mitreTactic}</div>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
              <div className="text-[11px] text-slate-400">MITRE Technique</div>
              <div className="text-xs font-semibold text-cyan-400 truncate mt-1">{incident.mitreTechnique}</div>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
              <div className="text-[11px] text-slate-400">Assigned Investigator</div>
              <div className="text-xs font-semibold text-white truncate mt-1">{incident.assignedTo}</div>
            </div>
          </div>

          {/* Tab Navigation */}
          <div className="flex border-b border-slate-800 font-mono text-xs">
            <button
              onClick={() => setActiveTab('OVERVIEW')}
              className={`pb-2.5 px-4 font-semibold transition-colors border-b-2 ${
                activeTab === 'OVERVIEW'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Overview & Containment
            </button>
            <button
              onClick={() => setActiveTab('TIMELINE')}
              className={`pb-2.5 px-4 font-semibold transition-colors border-b-2 ${
                activeTab === 'TIMELINE'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Timeline & Analyst Notes ({incident.timeline.length})
            </button>
            <button
              onClick={() => setActiveTab('ALERTS')}
              className={`pb-2.5 px-4 font-semibold transition-colors border-b-2 ${
                activeTab === 'ALERTS'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Linked Alerts ({incident.alertIds?.length || 0})
            </button>
            <button
              onClick={() => setActiveTab('TRACEABILITY')}
              className={`pb-2.5 px-4 font-semibold transition-colors border-b-2 flex items-center gap-1.5 ${
                activeTab === 'TRACEABILITY'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <GitMerge className="w-3.5 h-3.5 text-cyan-400" />
              <span>Traceability Chain</span>
            </button>
          </div>

          {/* TAB 1: OVERVIEW */}
          {activeTab === 'OVERVIEW' && (
            <div className="space-y-4">
              {/* Summary */}
              <div>
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5">
                  Incident Executive Summary
                </h4>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs leading-relaxed text-slate-300 font-mono">
                  {incident.summary}
                </div>
              </div>

              {/* Containment Recommendation & Response Simulation */}
              <div className="p-3.5 bg-amber-950/20 border border-amber-800/40 rounded-xl space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-mono uppercase tracking-wider text-amber-400 font-bold flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    Containment & Remediation Recommendation
                  </h4>
                  <button
                    id="btn-incident-simulate-response"
                    onClick={() => setIsSimulateModalOpen(true)}
                    className="px-3 py-1 bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs font-mono rounded-lg transition-colors flex items-center gap-1.5 shadow-md shadow-amber-500/10"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                    <span>[SIMULATE CONTAINMENT]</span>
                  </button>
                </div>
                <div className="p-2.5 bg-slate-950/60 rounded-lg border border-slate-800 text-xs leading-relaxed text-amber-200 font-mono">
                  {incident.containmentRecommendation}
                </div>
              </div>

              {/* Status Transition Control */}
              <div className="p-3.5 bg-slate-950 rounded-xl border border-slate-800 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <label className="text-xs font-mono text-slate-400 uppercase tracking-wider block">
                    Incident Lifecycle Actions:
                  </label>
                  <div className="flex items-center gap-2">
                    {incident.status !== 'ACKNOWLEDGED' && incident.status !== 'RESOLVED' && (
                      <button
                        id="btn-incident-quick-acknowledge"
                        type="button"
                        onClick={() => onUpdateStatus(incident.incidentId, 'ACKNOWLEDGED')}
                        className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-mono font-bold rounded-lg transition-colors flex items-center gap-1.5 shadow-md shadow-cyan-600/20"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Acknowledge Incident</span>
                      </button>
                    )}
                    {incident.status !== 'RESOLVED' && (
                      <button
                        id="btn-incident-quick-resolve"
                        type="button"
                        onClick={() => onUpdateStatus(incident.incidentId, 'RESOLVED')}
                        className="px-3 py-1 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-mono font-bold rounded-lg transition-colors flex items-center gap-1.5 shadow-md shadow-emerald-600/20"
                      >
                        <CheckCircle2 className="w-3.5 h-3.5" />
                        <span>Resolve Incident</span>
                      </button>
                    )}
                  </div>
                </div>

                <div className="flex flex-wrap gap-2 pt-1 border-t border-slate-900">
                  {(['NEW', 'ACKNOWLEDGED', 'INVESTIGATING', 'CONTAINED', 'RESOLVED'] as IncidentStatus[]).map(st => (
                    <button
                      key={st}
                      id={`btn-incident-status-${st.toLowerCase()}`}
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
            </div>
          )}

          {/* TAB 2: TIMELINE & ANALYST NOTES */}
          {activeTab === 'TIMELINE' && (
            <div className="space-y-3">
              <div className="max-h-64 overflow-y-auto space-y-2 pr-1 font-mono">
                {incident.timeline.map((entry, idx) => (
                  <div
                    key={idx}
                    className="flex items-start gap-3 p-2.5 rounded-lg bg-slate-950 border border-slate-800 text-xs"
                  >
                    <span className="text-slate-500 shrink-0 text-[11px] pt-0.5">{entry.time}</span>
                    <div className="flex-1">
                      <p className="text-slate-200">{entry.description}</p>
                      <span className="text-[10px] text-cyan-400">Actor: {entry.actor}</span>
                    </div>
                  </div>
                ))}
              </div>

              {/* Add Note Form */}
              <form onSubmit={handleAddNoteSubmit} className="flex gap-2 pt-2">
                <input
                  type="text"
                  placeholder="Record forensic investigator observation or containment note..."
                  value={newNote}
                  onChange={e => setNewNote(e.target.value)}
                  className="flex-1 px-3 py-2 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
                <button
                  type="submit"
                  disabled={!newNote.trim()}
                  className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-mono font-semibold inline-flex items-center gap-1.5 transition-colors disabled:opacity-50"
                >
                  <Send className="w-3.5 h-3.5" />
                  <span>Post Note</span>
                </button>
              </form>
            </div>
          )}

          {/* TAB 3: LINKED ALERTS */}
          {activeTab === 'ALERTS' && (
            <div className="space-y-2 font-mono text-xs">
              <div className="text-slate-400 text-xs mb-1">
                Security Alerts correlated under this incident dossier:
              </div>
              <div className="space-y-2 max-h-64 overflow-y-auto">
                {(incident.alertIds || []).map(altId => (
                  <div
                    key={altId}
                    className="p-3 bg-slate-950 rounded-xl border border-slate-800 flex items-center justify-between"
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-cyan-400">{altId}</span>
                      <span className="text-slate-300">Grouped Telemetry Event</span>
                    </div>
                    {onSelectAlert && (
                      <button
                        onClick={() => {
                          onClose();
                          onSelectAlert(altId);
                        }}
                        className="text-xs text-cyan-400 hover:text-cyan-300 flex items-center gap-1 underline"
                      >
                        <span>Inspect Alert</span>
                        <ExternalLink className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: END-TO-END TRACEABILITY CHAIN */}
          {activeTab === 'TRACEABILITY' && (
            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 bg-cyan-950/20 border border-cyan-800/40 rounded-lg text-cyan-300 text-xs leading-relaxed">
                Full forensic traceability mapping: Alert &rarr; Incident &rarr; Risk Assessment &rarr; Threat Detection &rarr; Correlation &rarr; Evidence &rarr; Ingested Log.
              </div>

              {traceChain ? (
                <div className="space-y-2 p-4 bg-slate-950 rounded-xl border border-slate-800">
                  <div className="flex items-center gap-2 text-slate-300">
                    <span className="text-slate-500 w-36 shrink-0">1. Alert ID:</span>
                    <span className="text-cyan-400 font-bold">{traceChain.alertId}</span>
                  </div>

                  <div className="flex items-center gap-2 text-slate-300">
                    <span className="text-slate-500 w-36 shrink-0">2. Incident ID:</span>
                    <span className="text-white font-bold">{traceChain.incidentId || incident.incidentId}</span>
                  </div>

                  <div className="flex items-center gap-2 text-slate-300">
                    <span className="text-slate-500 w-36 shrink-0">3. Risk Assessment:</span>
                    <span className="text-amber-400 font-bold">{traceChain.riskAssessmentId || 'Mapped from Stage 8 Engine'}</span>
                  </div>

                  <div className="flex items-center gap-2 text-slate-300">
                    <span className="text-slate-500 w-36 shrink-0">4. Threat Detection:</span>
                    <span className="text-purple-400 font-bold">{traceChain.threatDetectionId || 'ML Isolation Forest / Pattern Engine'}</span>
                  </div>

                  <div className="flex items-center gap-2 text-slate-300">
                    <span className="text-slate-500 w-36 shrink-0">5. Correlation ID:</span>
                    <span className="text-emerald-400 font-bold">{traceChain.correlationId || 'CORR-CROSS-AGENT'}</span>
                  </div>

                  <div className="flex items-center gap-2 text-slate-300">
                    <span className="text-slate-500 w-36 shrink-0">6. Agents:</span>
                    <span className="text-cyan-300">{traceChain.participatingAgents.join(', ')}</span>
                  </div>

                  <div className="pt-2 border-t border-slate-900">
                    <span className="text-slate-500 block mb-1">7. Forensic Telemetry Evidence:</span>
                    <div className="space-y-1">
                      {traceChain.evidence.slice(0, 3).map((ev, i) => (
                        <div key={i} className="p-2 bg-slate-900 rounded border border-slate-800 text-[11px] text-slate-300">
                          {ev}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-slate-400">
                  Select an alert associated with this incident to trace full correlation lineage.
                </div>
              )}
            </div>
          )}

          {/* Footer */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pt-4 border-t border-slate-800 gap-3">
            <form onSubmit={handleAssignSubmit} className="flex items-center gap-2">
              <User className="w-4 h-4 text-slate-400" />
              <input
                type="text"
                value={assigneeInput}
                onChange={e => setAssigneeInput(e.target.value)}
                placeholder="Assign investigator..."
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
              className="px-4 py-2 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-colors self-end sm:self-auto"
            >
              Close Incident
            </button>
          </div>
        </div>
      </div>

      {/* Safe Response Simulation Modal */}
      <SimulateResponseModal
        isOpen={isSimulateModalOpen}
        onClose={() => setIsSimulateModalOpen(false)}
        targetId={incident.incidentId}
        targetType="INCIDENT"
        defaultTargetEntity={incident.affectedSource}
      />
    </>
  );
};
