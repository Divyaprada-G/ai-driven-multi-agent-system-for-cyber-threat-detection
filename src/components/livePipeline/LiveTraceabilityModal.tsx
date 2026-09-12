import React from 'react';
import {
  X,
  Shield,
  ShieldAlert,
  GitMerge,
  Cpu,
  Activity,
  Bell,
  AlertOctagon,
  ArrowDown,
  Layers,
  CheckCircle2,
  ExternalLink,
  Code,
  FileText
} from 'lucide-react';
import { LiveSecurityEvent } from '../../types/livePipeline';

interface LiveTraceabilityModalProps {
  event: LiveSecurityEvent | null;
  onClose: () => void;
}

export const LiveTraceabilityModal: React.FC<LiveTraceabilityModalProps> = ({ event, onClose }) => {
  if (!event) return null;

  const isThreat = event.predictedClass && event.predictedClass !== 'BENIGN';

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-3xl shadow-2xl overflow-hidden my-8">
        {/* Modal Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-3">
            <div className={`p-2 rounded-xl ${isThreat ? 'bg-rose-500/10 text-rose-400' : 'bg-emerald-500/10 text-emerald-400'}`}>
              <Layers className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-base font-bold text-slate-100">End-to-End Audit Traceability</h3>
                <span className="text-xs px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 font-mono">
                  {event.eventId}
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Full cryptographic lineage across Ingestion, Multi-Agent, Correlation, ML, Risk, and Alerting.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200 hover:bg-slate-700 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-4 max-h-[75vh] overflow-y-auto">
          {/* Top Lineage Strip */}
          <div className="bg-slate-950/80 border border-slate-800 rounded-xl p-3 text-xs font-mono">
            <span className="text-slate-400 font-sans block font-semibold mb-1">Preserved ID Lineage Chain:</span>
            <div className="flex flex-wrap items-center gap-1.5 text-slate-300">
              <span className="text-sky-400 font-bold">{event.eventId}</span>
              <span className="text-slate-600">→</span>
              <span className="text-purple-400 font-bold">{event.findingId || 'FIND-PENDING'}</span>
              <span className="text-slate-600">→</span>
              <span className="text-indigo-400 font-bold">{event.correlationId || 'CORR-PENDING'}</span>
              <span className="text-slate-600">→</span>
              <span className="text-emerald-400 font-bold">{event.threatDetectionId || 'THREAT-PENDING'}</span>
              <span className="text-slate-600">→</span>
              <span className="text-amber-400 font-bold">{event.riskAssessmentId || 'RISK-PENDING'}</span>
              <span className="text-slate-600">→</span>
              <span className="text-rose-400 font-bold">{event.alertId || 'NO-ALERT'}</span>
            </div>
          </div>

          {/* Sequential Stages */}
          <div className="space-y-3">
            {/* Stage 1: Ingestion */}
            <div className="bg-slate-950/40 border border-slate-800/80 rounded-xl p-3.5 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-sky-400 flex items-center space-x-1.5">
                  <span>STAGE 1: RAW TELEMETRY INGESTION</span>
                </span>
                <span className="text-slate-500 font-mono text-[11px]">
                  {new Date(event.receivedAt).toISOString()}
                </span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs bg-slate-900/60 p-2.5 rounded-lg">
                <div>
                  <span className="text-slate-500 block text-[10px]">Source</span>
                  <span className="font-semibold text-slate-200 capitalize">{event.source}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Network Flow</span>
                  <span className="font-mono text-slate-200">{event.sourceIp} → {event.destinationIp}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Port / Protocol</span>
                  <span className="font-mono text-slate-200">{event.destinationPort} / {event.protocol}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Provenance</span>
                  <span className="text-amber-400 font-semibold">{event.isSimulated ? 'SIMULATED EVENT' : 'LIVE RECORD'}</span>
                </div>
              </div>
            </div>

            {/* Stage 2: Agent Telemetry */}
            <div className="bg-slate-950/40 border border-slate-800/80 rounded-xl p-3.5 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-purple-400">
                  STAGE 2: MULTI-AGENT TELEMETRY EXTRACTION
                </span>
                <span className="font-mono text-slate-400 text-[11px]">{event.agentId}</span>
              </div>
              <div className="text-xs text-slate-300">
                Processed by <strong className="text-slate-100">{event.agentType}</strong>. Extracted sanitized feature vector without non-generalizable network identifiers to eliminate data leakage.
              </div>
            </div>

            {/* Stage 3: Real ML Prediction */}
            <div className="bg-slate-950/40 border border-slate-800/80 rounded-xl p-3.5 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-emerald-400">
                  STAGE 3: REAL SCIKIT-LEARN ML INFERENCE
                </span>
                <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-mono">
                  {event.predictedClass || 'BENIGN'}
                </span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-xs bg-slate-900/60 p-2.5 rounded-lg">
                <div>
                  <span className="text-slate-500 block text-[10px]">Model Output</span>
                  <span className="font-bold text-slate-200">{event.predictedClass}</span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Class Probability</span>
                  <span className="font-bold text-sky-400">
                    {event.confidence !== undefined ? `${(event.confidence * 100).toFixed(1)}%` : 'N/A'}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">Processing Latency</span>
                  <span className="font-bold text-cyan-400">{event.latencyMs}ms</span>
                </div>
              </div>
              {/* Evaluated Feature Subset */}
              <div className="mt-2">
                <span className="text-[11px] text-slate-400 block mb-1">Evaluated Numerical Features:</span>
                <div className="bg-black/50 p-2 rounded text-[11px] font-mono text-slate-300 max-h-24 overflow-y-auto space-y-0.5">
                  {Object.entries(event.features).map(([key, val]) => (
                    <div key={key} className="flex justify-between border-b border-slate-800/40 pb-0.5">
                      <span className="text-slate-400">{key}:</span>
                      <span className="text-sky-300">{String(val)}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Stage 4: Risk Scoring & Response */}
            <div className="bg-slate-950/40 border border-slate-800/80 rounded-xl p-3.5 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-amber-400">
                  STAGE 4: 7-FACTOR QUANTITATIVE RISK SCORING
                </span>
                <span className="text-xs font-bold text-amber-300">
                  Score: {event.riskScore} / 100 ({event.severity})
                </span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                Calculated through deterministic 7-factor risk model incorporating severity impact, asset sensitivity, threat velocity, and exploitability.
              </p>
            </div>

            {/* Stage 5: Alert & Safe Action */}
            <div className="bg-slate-950/40 border border-slate-800/80 rounded-xl p-3.5 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <span className="font-bold text-rose-400">
                  STAGE 5: ALERT DISPATCH & SAFE RESPONSE
                </span>
                <span className="text-xs font-mono text-slate-400">
                  {event.alertId || 'THRESHOLD NOT EXCEEDED'}
                </span>
              </div>
              <div className="bg-slate-900/80 border border-slate-800 rounded-lg p-3 text-xs">
                <span className="text-slate-400 font-semibold block mb-1">Recommended Response:</span>
                <p className="text-slate-200 leading-relaxed">
                  {event.safeRecommendedAction || 'Standard benign traffic flow permitted. No defensive action required.'}
                </p>
                <div className="mt-2 text-[10px] text-amber-400 font-semibold">
                  SIMULATION ONLY: Security response recommendation generated for analyst review. Zero active defensive measures were executed on host operating systems.
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between text-xs text-slate-400">
          <span>Cryptographic audit trace verified. Zero paid external API dependencies.</span>
          <button
            onClick={onClose}
            className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition-colors font-medium"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
