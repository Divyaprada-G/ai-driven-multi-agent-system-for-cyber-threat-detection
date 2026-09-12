import React, { useState } from 'react';
import { CorrelatedEvent } from '../../types/correlation';
import {
  X,
  Layers,
  GitMerge,
  Clock,
  ShieldAlert,
  HardDrive,
  Server,
  User,
  ExternalLink,
  Code,
  Flame,
  CheckCircle2,
  Copy,
  Info
} from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';
import { StatusBadge } from '../common/StatusBadge';
import { CorrelationGraph } from './CorrelationGraph';
import { CorrelationTimeline } from './CorrelationTimeline';
import { CorrelationEvidencePanel } from './CorrelationEvidencePanel';

interface CorrelationDetailModalProps {
  event: CorrelatedEvent | null;
  onClose: () => void;
  onEscalate: (correlationId: string) => Promise<void>;
}

export const CorrelationDetailModal: React.FC<CorrelationDetailModalProps> = ({
  event,
  onClose,
  onEscalate
}) => {
  const [activeTab, setActiveTab] = useState<'overview' | 'graph' | 'timeline' | 'evidence' | 'json'>('overview');
  const [copied, setCopied] = useState(false);
  const [escalating, setEscalating] = useState(false);

  if (!event) return null;

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(event, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleEscalateClick = async () => {
    setEscalating(true);
    await onEscalate(event.id);
    setEscalating(false);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-6 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200"
      id="modal-correlation-detail"
      role="dialog"
      aria-modal="true"
    >
      <div className="w-full max-w-5xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl flex flex-col max-h-[90vh] overflow-hidden">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-start justify-between gap-4 bg-slate-950/70">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-mono text-cyan-400 font-bold bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800">
                {event.id}
              </span>
              <SeverityBadge severity={event.severity} />
              <span className={`text-xs font-mono px-2 py-0.5 rounded font-bold ${
                event.correlationStrength === 'HIGH'
                  ? 'bg-rose-950 text-rose-300 border border-rose-800'
                  : event.correlationStrength === 'MEDIUM'
                  ? 'bg-amber-950 text-amber-300 border border-amber-800'
                  : 'bg-slate-800 text-slate-300 border border-slate-700'
              }`}>
                Strength: {event.correlationStrength}
              </span>
              <span className="text-xs font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800">
                Confidence: {Math.round((event.correlationConfidence || 0) * 100)}%
              </span>
              <StatusBadge status={event.status} />
            </div>

            <h3 className="text-base sm:text-lg font-bold text-white tracking-tight">
              {event.title}
            </h3>
            <p className="text-xs text-slate-400 font-mono">
              Observed from {event.startTime} to {event.endTime} ({event.duration}) across {event.participatingAgents.length} agents
            </p>
          </div>

          <div className="flex items-center gap-2">
            {event.status !== 'ESCALATED' ? (
              <button
                id="btn-modal-escalate"
                onClick={handleEscalateClick}
                disabled={escalating}
                className="px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-mono font-bold inline-flex items-center gap-1.5 transition-colors shadow-sm"
              >
                <Flame className="w-3.5 h-3.5" />
                <span>{escalating ? 'Escalating...' : 'Escalate to Incident'}</span>
              </button>
            ) : (
              <span className="px-2.5 py-1 text-xs font-mono text-emerald-400 bg-emerald-950 border border-emerald-800 rounded-lg flex items-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Escalated (P0)</span>
              </span>
            )}

            <button
              id="btn-close-correlation-modal"
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              aria-label="Close"
            >
              <X className="w-5 h-5" />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="flex border-b border-slate-800 bg-slate-950/40 px-4 pt-2 gap-2 overflow-x-auto text-xs font-mono">
          {[
            { id: 'overview', label: 'Overview & Reasoning', icon: Info },
            { id: 'graph', label: 'Correlation Graph', icon: Layers },
            { id: 'timeline', label: 'Incident Timeline', icon: Clock },
            { id: 'evidence', label: 'Evidence Matrix', icon: GitMerge },
            { id: 'json', label: 'Raw Correlation JSON', icon: Code }
          ].map(tab => {
            const Icon = tab.icon;
            const isActive = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                id={`tab-modal-${tab.id}`}
                onClick={() => setActiveTab(tab.id as typeof activeTab)}
                className={`flex items-center gap-1.5 px-3 py-2 border-b-2 font-semibold transition-colors whitespace-nowrap ${
                  isActive
                    ? 'border-cyan-400 text-cyan-400 bg-slate-900/80 rounded-t-lg'
                    : 'border-transparent text-slate-400 hover:text-slate-200'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>

        {/* Modal Scrollable Body */}
        <div className="p-4 sm:p-6 overflow-y-auto space-y-6 flex-1 text-xs">
          {/* TAB 1: OVERVIEW & CAUSAL EXPLANATION */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Summary Card */}
              <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                <span className="text-[10px] font-mono uppercase tracking-wider text-cyan-400 font-bold">
                  Synthesized Incident Summary
                </span>
                <p className="text-xs text-slate-200 leading-relaxed font-sans">
                  {event.summary}
                </p>
              </div>

              {/* WHY WERE THESE EVENTS CONNECTED? */}
              <div className="p-4 sm:p-5 bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 border border-cyan-500/30 rounded-xl space-y-3">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
                  <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-300">
                    Why Were These Events Connected? (Causal Attribution)
                  </h4>
                </div>
                <div className="p-3 bg-slate-950/80 border border-slate-800/80 rounded-lg text-xs font-mono text-slate-200 whitespace-pre-line leading-relaxed">
                  {event.explanation}
                </div>
              </div>

              {/* Entity Badges Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1">
                  <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400">
                    <HardDrive className="w-3 h-3 text-cyan-400" />
                    <span>Source IP(s)</span>
                  </div>
                  <div className="text-xs font-mono font-bold text-slate-100">
                    {event.sourceIps.join(', ') || 'N/A'}
                  </div>
                </div>

                <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1">
                  <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400">
                    <Server className="w-3 h-3 text-emerald-400" />
                    <span>Affected Host(s)</span>
                  </div>
                  <div className="text-xs font-mono font-bold text-slate-100">
                    {event.hosts.join(', ') || 'Internal Infrastructure'}
                  </div>
                </div>

                <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-1">
                  <div className="flex items-center gap-1.5 text-[10px] font-mono text-slate-400">
                    <User className="w-3 h-3 text-purple-400" />
                    <span>Affected User(s)</span>
                  </div>
                  <div className="text-xs font-mono font-bold text-slate-100">
                    {event.users.join(', ') || 'System / Unauthenticated'}
                  </div>
                </div>
              </div>

              {/* Related Findings Table */}
              <div className="border border-slate-800 rounded-xl overflow-hidden bg-slate-950/60">
                <div className="p-3 border-b border-slate-800 flex items-center justify-between bg-slate-950">
                  <span className="text-xs font-mono font-bold text-slate-200">
                    Contributing Security Findings ({event.sequence?.length || event.findingIds.length})
                  </span>
                  <span className="text-[10px] font-mono text-slate-400">
                    Normalized Multi-Agent Findings
                  </span>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs font-mono">
                    <thead className="bg-slate-900/60 text-slate-400 uppercase text-[10px]">
                      <tr>
                        <th className="py-2.5 px-3">Step</th>
                        <th className="py-2.5 px-3">Timestamp</th>
                        <th className="py-2.5 px-3">Agent</th>
                        <th className="py-2.5 px-3">Detection / Activity</th>
                        <th className="py-2.5 px-3">Severity</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 text-slate-300">
                      {(event.sequence || []).map(step => (
                        <tr key={step.step} className="hover:bg-slate-800/30">
                          <td className="py-2.5 px-3 text-cyan-400 font-bold">#{step.step}</td>
                          <td className="py-2.5 px-3 text-slate-400">{step.timestamp.replace('T', ' ').substring(0, 19)}</td>
                          <td className="py-2.5 px-3 font-semibold text-slate-200">{step.agentId.replace('_', ' ')}</td>
                          <td className="py-2.5 px-3 max-w-[280px] truncate">{step.description}</td>
                          <td className="py-2.5 px-3"><SeverityBadge severity={step.severity} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: CORRELATION GRAPH */}
          {activeTab === 'graph' && (
            <CorrelationGraph correlatedEvent={event} />
          )}

          {/* TAB 3: TIMELINE */}
          {activeTab === 'timeline' && (
            <CorrelationTimeline
              correlatedEvent={event}
              onEscalate={event.status !== 'ESCALATED' ? handleEscalateClick : undefined}
            />
          )}

          {/* TAB 4: EVIDENCE MATRIX */}
          {activeTab === 'evidence' && (
            <CorrelationEvidencePanel correlatedEvent={event} />
          )}

          {/* TAB 5: RAW JSON */}
          {activeTab === 'json' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">
                  Serialized CorrelatedEvent object conforming to Stage 6 Specification:
                </span>
                <button
                  id="btn-copy-corr-json"
                  onClick={handleCopyJson}
                  className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono flex items-center gap-1.5 transition-colors border border-slate-700"
                >
                  {copied ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                </button>
              </div>

              <pre className="p-4 bg-slate-950 border border-slate-800 rounded-xl text-[11px] font-mono text-cyan-300 overflow-x-auto max-h-[500px]">
                {JSON.stringify(event, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="p-3 sm:p-4 border-t border-slate-800 bg-slate-950/70 flex items-center justify-between">
          <div className="text-[11px] font-mono text-slate-500">
            Defensive Security Analysis • Ready for downstream AI/ML Threat Detection Engine
          </div>
          <button
            id="btn-modal-footer-close"
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-mono font-semibold transition-colors border border-slate-700"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
