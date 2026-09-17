import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Clock,
  Terminal,
  Layers,
  Copy,
  Check,
  Flame,
  AlertTriangle,
  ChevronRight,
  ExternalLink,
  History,
  CheckCircle2,
  FileCode,
  Share2
} from 'lucide-react';
import { SecurityAlert, AlertLifecycleStatus } from '../../types/alertIncident';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import { alertManager } from '../../services/alertIncident/alertManager';
import { SimulateResponseModal } from './SimulateResponseModal';

interface AlertDetailModalProps {
  alert: SecurityAlert | null;
  onClose: () => void;
  onStatusUpdated?: (alertId: string, status: AlertLifecycleStatus) => void;
  onNavigateToIncident?: (incidentId: string) => void;
}

export const AlertDetailModal: React.FC<AlertDetailModalProps> = ({
  alert,
  onClose,
  onStatusUpdated,
  onNavigateToIncident
}) => {
  if (!alert) return null;

  const [activeTab, setActiveTab] = useState<'OVERVIEW' | 'EVIDENCE' | 'HISTORY' | 'N8N_PAYLOAD'>('OVERVIEW');
  const [isSimulateModalOpen, setIsSimulateModalOpen] = useState(false);
  const [isFalsePositivePromptOpen, setIsFalsePositivePromptOpen] = useState(false);
  const [falsePositiveReason, setFalsePositiveReason] = useState('');
  const [copiedPayload, setCopiedPayload] = useState(false);

  const n8nPayload = alertManager.generateN8nPayload(alert);

  const handleCopyPayload = () => {
    navigator.clipboard.writeText(JSON.stringify(n8nPayload, null, 2));
    setCopiedPayload(true);
    setTimeout(() => setCopiedPayload(false), 2000);
  };

  const handleStatusChange = (newStatus: AlertLifecycleStatus, reason?: string) => {
    alertManager.updateAlertStatus(alert.id, newStatus, reason);
    if (onStatusUpdated) onStatusUpdated(alert.id, newStatus);
  };

  const handleConfirmFalsePositive = (e: React.FormEvent) => {
    e.preventDefault();
    if (!falsePositiveReason.trim()) return;
    handleStatusChange('FALSE_POSITIVE', falsePositiveReason.trim());
    setIsFalsePositivePromptOpen(false);
    setFalsePositiveReason('');
  };

  const priorityColor =
    alert.priority === 'P1'
      ? 'bg-rose-950 text-rose-300 border-rose-700'
      : alert.priority === 'P2'
      ? 'bg-orange-950 text-orange-300 border-orange-700'
      : alert.priority === 'P3'
      ? 'bg-amber-950 text-amber-300 border-amber-700'
      : 'bg-blue-950 text-blue-300 border-blue-700';

  return (
    <>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/85 backdrop-blur-sm overflow-y-auto">
        <div
          id="modal-alert-detail"
          className="bg-slate-900 border border-slate-700 rounded-2xl max-w-4xl w-full p-6 shadow-2xl space-y-6 my-8 text-slate-200"
        >
          {/* Header */}
          <div className="flex items-start justify-between pb-4 border-b border-slate-800">
            <div className="space-y-1.5 max-w-2xl">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs px-2.5 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700 font-bold">
                  {alert.id}
                </span>
                <span className={`text-[11px] font-mono font-bold px-2 py-0.5 rounded border ${priorityColor}`}>
                  {alert.priority} PRIORITY
                </span>
                <SeverityBadge severity={alert.severity} size="md" />
                <StatusBadge status={alert.status} type="alert" />
                {alert.deduplicationCount > 1 && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-950/80 text-purple-300 border border-purple-800">
                    Deduplicated &times;{alert.deduplicationCount}
                  </span>
                )}
              </div>
              <h2 className="text-xl font-bold text-white tracking-tight">
                {alert.title}
              </h2>
              <p className="text-xs text-slate-400 font-mono">
                Detected: {alert.timestamp} • Last Seen: {alert.lastSeenTimestamp} • Source: {alert.source}
              </p>
            </div>
            <button
              id="btn-close-alert-modal"
              onClick={onClose}
              className="p-2 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Quick Metrics Bar */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
              <div className="text-[11px] text-slate-400">Risk Score</div>
              <div className="text-xl font-bold text-rose-400 mt-0.5">{alert.riskScore}/100</div>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
              <div className="text-[11px] text-slate-400">ML Confidence</div>
              <div className="text-xl font-bold text-cyan-400 mt-0.5">{alert.confidence}%</div>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
              <div className="text-[11px] text-slate-400">Threat Class</div>
              <div className="text-xs font-semibold text-slate-200 truncate mt-1">{alert.threatClassification}</div>
            </div>
            <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 font-mono">
              <div className="text-[11px] text-slate-400">Linked Incident</div>
              <div className="text-xs font-semibold text-cyan-400 truncate mt-1">
                {alert.incidentId ? (
                  <button
                    onClick={() => {
                      if (onNavigateToIncident && alert.incidentId) {
                        onClose();
                        onNavigateToIncident(alert.incidentId);
                      }
                    }}
                    className="hover:underline text-cyan-300 flex items-center gap-1"
                  >
                    <span>{alert.incidentId}</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                ) : (
                  <span className="text-slate-500">Unassigned</span>
                )}
              </div>
            </div>
          </div>

          {/* Navigation Tabs */}
          <div className="flex border-b border-slate-800 font-mono text-xs">
            <button
              onClick={() => setActiveTab('OVERVIEW')}
              className={`pb-2.5 px-4 font-semibold transition-colors border-b-2 ${
                activeTab === 'OVERVIEW'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Overview & Analysis
            </button>
            <button
              onClick={() => setActiveTab('EVIDENCE')}
              className={`pb-2.5 px-4 font-semibold transition-colors border-b-2 ${
                activeTab === 'EVIDENCE'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Untrusted Evidence ({alert.evidence.length})
            </button>
            <button
              onClick={() => setActiveTab('HISTORY')}
              className={`pb-2.5 px-4 font-semibold transition-colors border-b-2 ${
                activeTab === 'HISTORY'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Audit Trail ({alert.history.length})
            </button>
            <button
              onClick={() => setActiveTab('N8N_PAYLOAD')}
              className={`pb-2.5 px-4 font-semibold transition-colors border-b-2 flex items-center gap-1.5 ${
                activeTab === 'N8N_PAYLOAD'
                  ? 'border-cyan-500 text-cyan-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              <Share2 className="w-3.5 h-3.5 text-purple-400" />
              <span>Future n8n Payload</span>
            </button>
          </div>

          {/* Tab 1: OVERVIEW */}
          {activeTab === 'OVERVIEW' && (
            <div className="space-y-4">
              {/* Explicit Required Alert Information Specification Panel */}
              <div className="p-4 bg-slate-950/90 rounded-xl border border-cyan-900/50 shadow-inner space-y-3">
                <div className="flex items-center justify-between pb-2 border-b border-slate-800">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-mono uppercase tracking-wider text-cyan-300 font-bold">
                      Required Alert Information
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800">
                    Workflow Spec Compliant
                  </span>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 font-mono text-xs">
                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">1. Incident ID</span>
                    <span className="font-bold text-cyan-300">
                      {alert.incidentId ? (
                        <button
                          onClick={() => {
                            if (onNavigateToIncident && alert.incidentId) {
                              onClose();
                              onNavigateToIncident(alert.incidentId);
                            }
                          }}
                          className="hover:underline text-cyan-400 font-bold inline-flex items-center gap-1"
                        >
                          {alert.incidentId}
                          <ExternalLink className="w-3 h-3" />
                        </button>
                      ) : (
                        'INC-PENDING'
                      )}
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">2. Detection Timestamp</span>
                    <span className="text-slate-200">{alert.timestamp}</span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">3. Agent Name</span>
                    <span className="text-emerald-400 font-semibold">
                      {alert.agentName || (alert.participatingAgents && alert.participatingAgents.length > 0 ? alert.participatingAgents.join(', ') : 'NetworkAgent')}
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">4. Threat Category</span>
                    <span className="text-purple-300 font-semibold">
                      {alert.threatCategory || alert.threatClassification || alert.alertType}
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">5. Severity</span>
                    <div className="mt-0.5">
                      <SeverityBadge severity={alert.severity} size="sm" />
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800">
                    <span className="text-[10px] text-slate-400 uppercase block">6. Incident Status</span>
                    <div className="mt-0.5">
                      <StatusBadge status={alert.incidentStatus || alert.status} type="incident" />
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 sm:col-span-2 lg:col-span-3">
                    <span className="text-[10px] text-slate-400 uppercase block">7. Detection Method</span>
                    <span className="text-cyan-300">
                      {alert.detectionMethod || alert.ruleTriggered || 'Multi-Agent Correlation & Statistical Entropy Engine'}
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 sm:col-span-2 lg:col-span-3">
                    <span className="text-[10px] text-slate-400 uppercase block">8. Description</span>
                    <span className="text-slate-300 leading-relaxed block mt-0.5">
                      {alert.description || alert.explanation}
                    </span>
                  </div>

                  <div className="p-2.5 rounded-lg bg-slate-900/80 border border-slate-800 sm:col-span-2 lg:col-span-3">
                    <span className="text-[10px] text-slate-400 uppercase block">9. Evidence</span>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {alert.evidence && alert.evidence.length > 0 ? (
                        alert.evidence.map((ev, i) => (
                          <span key={i} className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 text-[11px]">
                            {ev}
                          </span>
                        ))
                      ) : (
                        <span className="text-slate-500">Telemetry indicators recorded</span>
                      )}
                    </div>
                  </div>

                  <div className="p-2.5 rounded-lg bg-amber-950/30 border border-amber-800/60 sm:col-span-2 lg:col-span-3">
                    <span className="text-[10px] text-amber-400 uppercase block font-bold">10. Recommended Action</span>
                    <span className="text-amber-200 font-semibold block mt-0.5">
                      {alert.recommendedAction}
                    </span>
                  </div>
                </div>
              </div>

              {/* Explanation & Causal Attribution */}
              <div>
                <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-1.5">
                  AI/ML Detection Explanation & Attribution
                </h4>
                <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 text-xs text-slate-300 leading-relaxed font-mono">
                  {alert.explanation}
                </div>
              </div>

              {/* Recommended Action & Simulation CTA */}
              <div className="p-3.5 bg-amber-950/20 border border-amber-800/40 rounded-xl space-y-2">
                <div className="flex items-center justify-between">
                  <div className="text-xs font-mono uppercase tracking-wider text-amber-300 font-bold flex items-center gap-1.5">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    Recommended Containment Action
                  </div>
                  <button
                    id="btn-alert-open-simulate"
                    onClick={() => setIsSimulateModalOpen(true)}
                    className="px-3 py-1 bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold text-xs font-mono rounded-lg transition-colors flex items-center gap-1.5 shadow-md shadow-amber-500/10"
                  >
                    <Terminal className="w-3.5 h-3.5" />
                    <span>[SIMULATE RESPONSE]</span>
                  </button>
                </div>
                <div className="text-xs text-amber-200/90 font-mono">
                  {alert.recommendedAction}
                </div>
              </div>

              {/* Multi-Agent Context & Entities */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1.5">
                  <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                    Participating Security Agents
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {alert.participatingAgents.map(ag => (
                      <span
                        key={ag}
                        className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 text-[11px] font-mono"
                      >
                        {ag}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="p-3 bg-slate-950 rounded-xl border border-slate-800 space-y-1.5">
                  <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                    Affected Network & Host Entities
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {alert.affectedEntities.map(ent => (
                      <span
                        key={ent}
                        className="px-2 py-0.5 rounded bg-slate-900 text-slate-300 border border-slate-700 text-[11px] font-mono"
                      >
                        {ent}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Simulated Response Records (if any executed) */}
              {alert.simulatedResponses.length > 0 && (
                <div className="p-3 bg-slate-950 rounded-xl border border-emerald-900/50 space-y-2">
                  <div className="text-xs font-mono text-emerald-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                    Simulated Responses Executed on this Alert:
                  </div>
                  <div className="space-y-1.5">
                    {alert.simulatedResponses.map(r => (
                      <div key={r.id} className="text-xs font-mono text-slate-300 bg-slate-900/80 p-2 rounded border border-slate-800 flex justify-between items-center">
                        <span>{r.title} &rarr; <strong className="text-white">{r.target}</strong></span>
                        <span className="text-[10px] text-slate-500">{r.timestamp}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Tab 2: UNTRUSTED EVIDENCE */}
          {activeTab === 'EVIDENCE' && (
            <div className="space-y-3">
              <div className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs text-slate-400 flex items-center justify-between font-mono">
                <span className="text-amber-400 font-bold uppercase">Untrusted Raw Telemetry View</span>
                <span>Rendered securely as escaped text</span>
              </div>
              <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs text-slate-300 max-h-72 overflow-y-auto space-y-2">
                {alert.evidence.map((ev, idx) => (
                  <div key={idx} className="p-2 rounded bg-slate-900/60 border border-slate-800/80 text-slate-300 break-all select-text">
                    <span className="text-cyan-400 mr-2">[{idx + 1}]</span>
                    {ev}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Tab 3: AUDIT TRAIL & HISTORY */}
          {activeTab === 'HISTORY' && (
            <div className="space-y-2 max-h-80 overflow-y-auto pr-2 font-mono text-xs">
              {alert.history.map(item => (
                <div key={item.id} className="p-2.5 rounded-lg bg-slate-950 border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between text-[11px]">
                    <span className="font-bold text-cyan-400">{item.action}</span>
                    <span className="text-slate-500">{item.timestamp}</span>
                  </div>
                  <p className="text-slate-300">{item.details}</p>
                  <div className="text-[10px] text-slate-500">Actor: {item.actor}</div>
                </div>
              ))}
            </div>
          )}

          {/* Tab 4: FUTURE N8N WEBHOOK PAYLOAD */}
          {activeTab === 'N8N_PAYLOAD' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between p-3 bg-purple-950/20 border border-purple-800/40 rounded-lg">
                <div className="text-xs font-mono text-purple-300">
                  <strong>Section 41 & 42:</strong> Prepared Payload Structure for future n8n automation dispatch.
                </div>
                <button
                  type="button"
                  onClick={handleCopyPayload}
                  className="px-3 py-1 bg-purple-600 hover:bg-purple-500 text-white rounded-lg text-xs font-mono inline-flex items-center gap-1.5 transition-colors"
                >
                  {copiedPayload ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copiedPayload ? 'Copied JSON' : 'Copy JSON'}</span>
                </button>
              </div>
              <pre className="p-4 bg-slate-950 rounded-xl border border-slate-800 font-mono text-xs text-purple-200 overflow-x-auto max-h-72 select-all">
                {JSON.stringify(n8nPayload, null, 2)}
              </pre>
            </div>
          )}

          {/* False Positive Reason Form */}
          {isFalsePositivePromptOpen && (
            <form onSubmit={handleConfirmFalsePositive} className="p-4 bg-rose-950/20 border border-rose-800/60 rounded-xl space-y-3 font-mono">
              <div className="text-xs font-bold text-rose-300 uppercase tracking-wider">
                Specify Reason for Marking as False Positive:
              </div>
              <input
                type="text"
                required
                value={falsePositiveReason}
                onChange={e => setFalsePositiveReason(e.target.value)}
                placeholder="e.g. Authorized penetration test, Scheduled maintenance backup, Benign administrator script..."
                className="w-full px-3 py-2 text-xs bg-slate-950 border border-slate-700 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500"
              />
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setIsFalsePositivePromptOpen(false)}
                  className="px-3 py-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1 text-xs bg-rose-600 hover:bg-rose-500 text-white font-bold rounded-lg transition-colors"
                >
                  Confirm False Positive
                </button>
              </div>
            </form>
          )}

          {/* Lifecycle Action Bar */}
          <div className="pt-4 border-t border-slate-800 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono text-slate-400">Lifecycle:</span>
              {alert.status === 'NEW' && (
                <button
                  id="btn-alert-acknowledge"
                  onClick={() => handleStatusChange('ACKNOWLEDGED', 'Triage acknowledged by analyst')}
                  className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-white rounded-lg text-xs font-mono font-semibold transition-colors"
                >
                  Acknowledge
                </button>
              )}
              {alert.status !== 'INVESTIGATING' && (
                <button
                  id="btn-alert-investigate"
                  onClick={() => handleStatusChange('INVESTIGATING', 'Escalated to investigation')}
                  className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono border border-slate-700 transition-colors"
                >
                  Investigate
                </button>
              )}
              {alert.status !== 'RESOLVED' && (
                <button
                  id="btn-alert-resolve"
                  onClick={() => handleStatusChange('RESOLVED', 'Issue verified mitigated and resolved')}
                  className="px-3 py-1 bg-emerald-700 hover:bg-emerald-600 text-white rounded-lg text-xs font-mono font-semibold transition-colors"
                >
                  Resolve
                </button>
              )}
              {alert.status !== 'FALSE_POSITIVE' && (
                <button
                  id="btn-alert-false-positive"
                  onClick={() => setIsFalsePositivePromptOpen(true)}
                  className="px-3 py-1 bg-slate-800 hover:bg-rose-950 text-slate-400 hover:text-rose-300 rounded-lg text-xs font-mono border border-slate-700 transition-colors"
                >
                  False Positive
                </button>
              )}
            </div>

            <button
              onClick={onClose}
              className="px-4 py-1.5 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-700 transition-colors self-end sm:self-auto"
            >
              Close Alert
            </button>
          </div>
        </div>
      </div>

      {/* Nested Safe Response Simulation Modal */}
      <SimulateResponseModal
        isOpen={isSimulateModalOpen}
        onClose={() => setIsSimulateModalOpen(false)}
        targetId={alert.id}
        targetType="ALERT"
        defaultTargetEntity={alert.source}
      />
    </>
  );
};
