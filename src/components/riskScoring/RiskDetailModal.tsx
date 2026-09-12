/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Explainable Risk Detail Modal
 *
 * Provides complete transparent visibility into:
 * - Risk Score, Severity, Priority
 * - Explicit distinction: Severity vs Confidence vs Correlation vs Risk
 * - 7-Factor Weighted Breakdown table
 * - Explainable AI derivation text
 * - Safe recommended non-destructive mitigation
 * - Traceability audit trail
 * - Prepared n8n Webhook Payload preview (Section 33)
 */

import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  Flame,
  AlertTriangle,
  ShieldCheck,
  Cpu,
  Layers,
  CheckCircle2,
  Copy,
  Check,
  FileCode,
  Network,
  Server,
  Globe,
  Info,
  ExternalLink
} from 'lucide-react';
import { RiskAssessment, RiskStatus } from '../../types/riskScoring';
import { SeverityBadge } from '../common/SeverityBadge';
import { N8nPayloadGenerator } from '../../services/riskScoring/n8nPayloadGenerator';

interface RiskDetailModalProps {
  assessment: RiskAssessment | null;
  onClose: () => void;
  onUpdateStatus?: (id: string, newStatus: RiskStatus) => void;
}

export const RiskDetailModal: React.FC<RiskDetailModalProps> = ({
  assessment,
  onClose,
  onUpdateStatus
}) => {
  const [activeTab, setActiveTab] = useState<'EXPLANATION' | 'FACTORS' | 'N8N_PAYLOAD' | 'AUDIT'>('EXPLANATION');
  const [copied, setCopied] = useState(false);

  if (!assessment) return null;

  const n8nJson = N8nPayloadGenerator.generatePrettyJson(assessment);

  const handleCopy = () => {
    navigator.clipboard.writeText(n8nJson);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getPriorityColor = (priority: string) => {
    switch (priority) {
      case 'P1':
        return 'text-rose-400 bg-rose-950/60 border-rose-800';
      case 'P2':
        return 'text-orange-400 bg-orange-950/60 border-orange-800';
      case 'P3':
        return 'text-amber-400 bg-amber-950/60 border-amber-800';
      case 'P4':
      default:
        return 'text-blue-400 bg-blue-950/60 border-blue-800';
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-black/80 backdrop-blur-sm overflow-y-auto"
      id="modal-risk-detail"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-4xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl overflow-hidden my-auto"
        onClick={e => e.stopPropagation()}
      >
        {/* Header Bar */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/70">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-cyan-950 border border-cyan-800 text-cyan-400">
              <ShieldAlert className="w-6 h-6" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono font-bold text-cyan-400">
                  {assessment.id}
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getPriorityColor(assessment.priority)}`}>
                  {assessment.priority} {assessment.riskBand}
                </span>
                <SeverityBadge severity={assessment.severity} size="sm" />
              </div>
              <h3 className="text-base sm:text-lg font-bold text-white tracking-tight mt-0.5">
                {String(assessment.threatClassification)}
              </h3>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Conceptual Distinction Banner: Severity vs Confidence vs Correlation vs Risk */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 p-3 bg-slate-950/90 border-b border-slate-800 text-xs font-mono">
          <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
            <div className="text-[10px] text-slate-400 uppercase">1. Threat Severity</div>
            <div className="text-sm font-bold text-white mt-0.5 flex items-center justify-between">
              <span>{assessment.severity}</span>
              <span className="text-[11px] text-slate-400 font-normal">Impact potential</span>
            </div>
          </div>

          <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
            <div className="text-[10px] text-slate-400 uppercase">2. ML Confidence</div>
            <div className="text-sm font-bold text-emerald-400 mt-0.5 flex items-center justify-between">
              <span>{assessment.confidence}%</span>
              <span className="text-[11px] text-slate-400 font-normal">Certainty</span>
            </div>
          </div>

          <div className="p-2 rounded bg-slate-900/80 border border-slate-800">
            <div className="text-[10px] text-slate-400 uppercase">3. Correlation Strength</div>
            <div className="text-sm font-bold text-cyan-400 mt-0.5 flex items-center justify-between">
              <span>{assessment.auditTrail.correlationStrength}/100</span>
              <span className="text-[11px] text-slate-400 font-normal">Cross-agent link</span>
            </div>
          </div>

          <div className="p-2 rounded bg-indigo-950/50 border border-indigo-800/80">
            <div className="text-[10px] text-indigo-300 uppercase font-bold">4. Synthesized Risk</div>
            <div className="text-sm font-bold text-indigo-200 mt-0.5 flex items-center justify-between">
              <span className="text-base">{assessment.riskScore}/100</span>
              <span className="text-[11px] text-indigo-400 font-normal">{assessment.priority} Priority</span>
            </div>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-slate-800 px-4 pt-2 gap-2 bg-slate-950/40 text-xs font-mono">
          <button
            onClick={() => setActiveTab('EXPLANATION')}
            className={`px-3 py-2 border-b-2 font-bold transition-colors ${
              activeTab === 'EXPLANATION'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Explainable Breakdown
          </button>
          <button
            onClick={() => setActiveTab('FACTORS')}
            className={`px-3 py-2 border-b-2 font-bold transition-colors ${
              activeTab === 'FACTORS'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Weighted Factor Math ({assessment.riskFactors.length})
          </button>
          <button
            onClick={() => setActiveTab('N8N_PAYLOAD')}
            className={`px-3 py-2 border-b-2 font-bold transition-colors flex items-center gap-1.5 ${
              activeTab === 'N8N_PAYLOAD'
                ? 'border-purple-400 text-purple-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Prepared n8n Webhook</span>
          </button>
          <button
            onClick={() => setActiveTab('AUDIT')}
            className={`px-3 py-2 border-b-2 font-bold transition-colors ${
              activeTab === 'AUDIT'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Traceability Audit
          </button>
        </div>

        {/* Tab Contents */}
        <div className="p-4 sm:p-5 max-h-[60vh] overflow-y-auto space-y-4">
          {/* TAB 1: EXPLANATION */}
          {activeTab === 'EXPLANATION' && (
            <div className="space-y-4">
              {/* Natural Language Explanation Box */}
              <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                <div className="flex items-center gap-2 text-xs font-mono text-cyan-400">
                  <Info className="w-4 h-4" />
                  <span className="font-bold uppercase tracking-wider">Deterministic AI Explanation</span>
                </div>
                <p className="text-sm text-slate-200 leading-relaxed font-sans">
                  {assessment.explanation}
                </p>
              </div>

              {/* Recommended Action Box */}
              <div className="p-4 rounded-xl bg-gradient-to-r from-slate-950 via-slate-900 to-slate-950 border border-slate-800 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold">
                    Safe Recommended Mitigation (Non-Destructive)
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800">
                    ADVISORY ONLY
                  </span>
                </div>
                <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-cyan-300 flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <span>{assessment.recommendedAction}</span>
                </div>
                <p className="text-[11px] text-slate-500 font-mono">
                  Defensive guideline: The system does not automatically block IPs, isolate hosts, or execute shell commands.
                </p>
              </div>

              {/* Multi-Agent Architecture Findings */}
              <div className="space-y-2">
                <span className="text-xs font-mono uppercase tracking-wider text-slate-400 font-bold">
                  Participating Specialized Agents & Evidence
                </span>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 font-mono text-xs">
                  {assessment.participatingAgents.map(agent => (
                    <div
                      key={agent}
                      className="p-2.5 rounded-lg bg-slate-950/70 border border-slate-800 flex items-center gap-2"
                    >
                      {agent === 'NETWORK_AGENT' && <Network className="w-4 h-4 text-cyan-400 shrink-0" />}
                      {agent === 'SYSTEM_AGENT' && <Server className="w-4 h-4 text-emerald-400 shrink-0" />}
                      {agent === 'APPLICATION_AGENT' && <Globe className="w-4 h-4 text-purple-400 shrink-0" />}
                      <div>
                        <div className="font-bold text-white text-[11px]">{agent.replace('_', ' ')}</div>
                        <div className="text-[10px] text-slate-400">Telemetry Active</div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: WEIGHTED FACTOR MATH */}
          {activeTab === 'FACTORS' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400 pb-2 border-b border-slate-800">
                <span>Weighted Mathematical Breakdown (Academic / Demo Formula)</span>
                <span className="text-white font-bold">
                  Total Score = {assessment.riskScore}/100
                </span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono text-slate-300">
                  <thead className="bg-slate-950/70 text-slate-400 uppercase text-[10px] border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Factor Name</th>
                      <th className="py-2.5 px-3">Raw (0-100)</th>
                      <th className="py-2.5 px-3">Weight</th>
                      <th className="py-2.5 px-3">Weighted Pts</th>
                      <th className="py-2.5 px-3">Evidence Basis</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {assessment.riskFactors.map(f => (
                      <tr key={f.name} className="hover:bg-slate-800/30">
                        <td className="py-2.5 px-3 font-bold text-white">{f.label}</td>
                        <td className="py-2.5 px-3">
                          <span className="text-cyan-400">{f.rawScore}</span>
                          <span className="text-slate-500 text-[10px]">/100</span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-400">
                          {Math.round(f.weight * 100)}%
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="text-emerald-400 font-bold">
                            {f.weightedScore.toFixed(1)}
                          </span>
                          <span className="text-slate-500 text-[10px]">
                            {' '}/ {f.maxPossibleWeightedScore}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-[11px] text-slate-400 max-w-[280px]">
                          {f.description}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                  <tfoot className="bg-slate-950 border-t border-slate-800 font-bold">
                    <tr>
                      <td className="py-2.5 px-3 text-white">Aggregated Risk Sum</td>
                      <td className="py-2.5 px-3 text-slate-400">—</td>
                      <td className="py-2.5 px-3 text-slate-400">100%</td>
                      <td className="py-2.5 px-3 text-cyan-400 text-sm">
                        {assessment.riskScore}/100
                      </td>
                      <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                        Clamped to [0, 100], mapped to {assessment.priority} ({assessment.riskBand})
                      </td>
                    </tr>
                  </tfoot>
                </table>
              </div>
            </div>
          )}

          {/* TAB 3: PREPARED N8N WEBHOOK PAYLOAD */}
          {activeTab === 'N8N_PAYLOAD' && (
            <div className="space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 bg-purple-950/20 border border-purple-800/40 rounded-lg text-xs font-mono text-purple-300">
                <div className="flex items-center gap-2">
                  <FileCode className="w-4 h-4 text-purple-400 shrink-0" />
                  <span>
                    Output structure prepared for downstream n8n webhook ingestion (Section 33).
                  </span>
                </div>
                <button
                  onClick={handleCopy}
                  className="px-2.5 py-1 rounded bg-purple-900/60 hover:bg-purple-800 text-purple-200 border border-purple-700 flex items-center gap-1.5 transition-colors self-end sm:self-auto"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                </button>
              </div>

              <pre className="p-4 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-slate-300 overflow-x-auto max-h-[300px]">
                {n8nJson}
              </pre>
              <p className="text-[11px] text-slate-500 font-mono">
                * Note: In compliance with prompt directives, no live network webhook triggers are initiated in this stage.
              </p>
            </div>
          )}

          {/* TAB 4: TRACEABILITY AUDIT */}
          {activeTab === 'AUDIT' && (
            <div className="space-y-3 font-mono text-xs">
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-800 space-y-2">
                <span className="text-slate-400 uppercase text-[10px] font-bold">Audit Lineage</span>
                <div className="flex flex-col gap-1.5 text-slate-300">
                  <div>1. Threat Detection ID: <strong className="text-cyan-400">{assessment.threatDetectionId}</strong></div>
                  <div>2. Correlation ID: <strong className="text-cyan-400">{assessment.correlationId}</strong></div>
                  <div>3. Target Affected Asset: <strong className="text-white">{assessment.affectedSource}</strong></div>
                  <div>4. Model Engine: <strong className="text-white">{assessment.auditTrail.modelUsed}</strong></div>
                  <div>5. Weights Config Version: <strong className="text-white">{assessment.auditTrail.weightsConfigVersion}</strong></div>
                  <div>6. Calculated At: <strong className="text-slate-400">{assessment.auditTrail.calculatedAt}</strong></div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Footer: Status Controller */}
        <div className="p-4 border-t border-slate-800 bg-slate-950 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs font-mono">
          <div className="flex items-center gap-2 text-slate-400">
            <span>Triage Status:</span>
            <span className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-white font-bold">
              {assessment.status}
            </span>
          </div>

          <div className="flex items-center gap-1.5 flex-wrap">
            <span className="text-[11px] text-slate-500 mr-1">Update Status:</span>
            {(['NEW', 'REVIEWING', 'ACKNOWLEDGED', 'RESOLVED', 'FALSE_POSITIVE'] as RiskStatus[]).map(st => (
              <button
                key={st}
                onClick={() => onUpdateStatus && onUpdateStatus(assessment.id, st)}
                className={`px-2.5 py-1 rounded text-[10px] border transition-colors ${
                  assessment.status === st
                    ? 'bg-cyan-950 text-cyan-300 border-cyan-500 font-bold shadow-sm'
                    : 'bg-slate-900 hover:bg-slate-800 text-slate-400 border-slate-800'
                }`}
              >
                {st}
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
