import React, { useState } from 'react';
import { SystemAgentResult } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import {
  X,
  ShieldAlert,
  ArrowRight,
  Terminal,
  Copy,
  Check,
  CheckCircle2,
  AlertTriangle,
  Lightbulb,
  FileCode,
  Server,
  User,
  Activity
} from 'lucide-react';

interface SystemDetailModalProps {
  result: SystemAgentResult | null;
  onClose: () => void;
}

export const SystemDetailModal: React.FC<SystemDetailModalProps> = ({
  result,
  onClose
}) => {
  const [copied, setCopied] = useState(false);
  const [tab, setTab] = useState<'evidence' | 'raw'>('evidence');

  if (!result) return null;

  const handleCopyRaw = () => {
    const text = JSON.stringify(result.rawEvent || result, null, 2);
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div
      className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto"
      id="modal-system-detail"
      onClick={onClose}
    >
      <div
        className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-3xl shadow-2xl overflow-hidden my-8"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-5 border-b border-slate-800 bg-slate-950/80 flex items-start justify-between gap-4">
          <div className="space-y-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-mono text-emerald-400 font-semibold uppercase tracking-wider">
                Detection #{result.id}
              </span>
              <SeverityBadge severity={result.severity} />
              <span className="px-2 py-0.5 rounded bg-slate-800 text-[11px] font-mono text-slate-300 border border-slate-700">
                Confidence: {(result.confidence * 100).toFixed(0)}%
              </span>
              <span
                className={`px-2 py-0.5 rounded text-[11px] font-mono uppercase font-bold ${
                  result.classification === 'THREAT'
                    ? 'bg-rose-950/80 text-rose-300 border border-rose-800'
                    : result.classification === 'SUSPICIOUS'
                    ? 'bg-amber-950/80 text-amber-300 border border-amber-800'
                    : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
                }`}
              >
                {result.classification}
              </span>
            </div>
            <h2 className="text-lg font-bold text-white font-sans mt-1">
              {result.detection}
            </h2>
          </div>

          <button
            id="btn-close-system-modal"
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Visual 3-Step Detection Reasoning Path */}
        <div className="p-4 bg-slate-950/60 border-b border-slate-800">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 font-semibold">
            Explainable Detection Reasoning Path
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Step 1: Observed Activity */}
            <div className="p-3 bg-slate-900/90 border border-slate-800 rounded-lg">
              <div className="flex items-center gap-1.5 text-xs font-mono text-cyan-400 font-semibold mb-1">
                <span className="w-4 h-4 rounded-full bg-cyan-950 text-cyan-400 border border-cyan-700 flex items-center justify-center text-[10px]">
                  1
                </span>
                <span>Observed Activity</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                {result.observedActivity}
              </p>
            </div>

            {/* Step 2: Detected Pattern */}
            <div className="p-3 bg-slate-900/90 border border-slate-800 rounded-lg">
              <div className="flex items-center gap-1.5 text-xs font-mono text-amber-400 font-semibold mb-1">
                <span className="w-4 h-4 rounded-full bg-amber-950 text-amber-400 border border-amber-700 flex items-center justify-center text-[10px]">
                  2
                </span>
                <span>Detected Pattern</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                {result.detectedPattern}
              </p>
            </div>

            {/* Step 3: Security Finding */}
            <div className="p-3 bg-slate-900/90 border border-slate-800 rounded-lg">
              <div className="flex items-center gap-1.5 text-xs font-mono text-rose-400 font-semibold mb-1">
                <span className="w-4 h-4 rounded-full bg-rose-950 text-rose-400 border border-rose-700 flex items-center justify-center text-[10px]">
                  3
                </span>
                <span>Security Finding</span>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed font-sans">
                {result.securityFinding}
              </p>
            </div>
          </div>
        </div>

        {/* Tab Selector */}
        <div className="flex items-center gap-4 px-5 pt-3 border-b border-slate-800 bg-slate-950/40 text-xs font-mono">
          <button
            onClick={() => setTab('evidence')}
            className={`pb-2.5 font-semibold transition-colors border-b-2 flex items-center gap-1.5 ${
              tab === 'evidence'
                ? 'border-emerald-400 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            <span>Forensic Evidence & Metadata</span>
          </button>
          <button
            onClick={() => setTab('raw')}
            className={`pb-2.5 font-semibold transition-colors border-b-2 flex items-center gap-1.5 ${
              tab === 'raw'
                ? 'border-emerald-400 text-emerald-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode className="w-3.5 h-3.5" />
            <span>Raw Log & Correlation Payload</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-5 space-y-5 max-h-[50vh] overflow-y-auto">
          {tab === 'evidence' ? (
            <>
              {/* Endpoint Context Bar */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs font-mono">
                <div>
                  <div className="text-slate-500 text-[10px] uppercase flex items-center gap-1">
                    <Server className="w-3 h-3 text-indigo-400" />
                    <span>Host / Computer</span>
                  </div>
                  <div className="font-bold text-slate-200 mt-0.5">{result.host}</div>
                </div>
                <div>
                  <div className="text-slate-500 text-[10px] uppercase flex items-center gap-1">
                    <User className="w-3 h-3 text-emerald-400" />
                    <span>User Account</span>
                  </div>
                  <div className="font-bold text-slate-200 mt-0.5">{result.username}</div>
                </div>
                <div>
                  <div className="text-slate-500 text-[10px] uppercase">Client / Source IP</div>
                  <div className="font-bold text-slate-200 mt-0.5">{result.sourceIp || 'Internal / N/A'}</div>
                </div>
                <div>
                  <div className="text-slate-500 text-[10px] uppercase">Event Category</div>
                  <div className="font-bold text-slate-200 mt-0.5">{result.eventType}</div>
                </div>
              </div>

              {/* Command Line / Process if available */}
              {(result.commandLine || result.processName) && (
                <div className="p-3 bg-slate-950/90 border border-slate-800 rounded-lg space-y-1">
                  <div className="text-[11px] font-mono text-slate-400 uppercase font-semibold flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Process & Command Telemetry</span>
                  </div>
                  {result.processName && (
                    <div className="text-xs font-mono text-slate-300">
                      <span className="text-slate-500">Process Image:</span> {result.processName}
                    </div>
                  )}
                  {result.commandLine && (
                    <div className="p-2 bg-black/60 rounded border border-slate-800 text-xs font-mono text-amber-300 break-all">
                      {result.commandLine}
                    </div>
                  )}
                </div>
              )}

              {/* Evidence Statements */}
              <div className="space-y-2">
                <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Explainable Evidence Statements</span>
                </div>
                <ul className="space-y-1.5">
                  {result.evidence.map((stmt, idx) => (
                    <li
                      key={idx}
                      className="text-xs text-slate-300 bg-slate-950/40 p-2.5 rounded-lg border border-slate-800/80 flex items-start gap-2"
                    >
                      <span className="text-emerald-400 font-mono mt-0.5">•</span>
                      <span className="font-sans leading-relaxed">{stmt}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {/* Observable Indicators */}
              <div className="space-y-2">
                <div className="text-xs font-mono uppercase tracking-wider text-slate-400 font-semibold flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  <span>Observable System Indicators</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {result.indicators.map((ind, idx) => (
                    <span
                      key={idx}
                      className="px-2.5 py-1 rounded bg-slate-800/90 text-slate-300 border border-slate-700 text-xs font-mono"
                    >
                      {ind}
                    </span>
                  ))}
                </div>
              </div>

              {/* Recommended Action (Informational / Advisory Only) */}
              <div className="p-3.5 bg-cyan-950/30 border border-cyan-800/60 rounded-lg space-y-1">
                <div className="flex items-center gap-1.5 text-xs font-mono text-cyan-400 font-bold uppercase tracking-wider">
                  <Lightbulb className="w-4 h-4" />
                  <span>Recommended Action (Advisory Only)</span>
                </div>
                <p className="text-xs text-cyan-200/90 leading-relaxed font-sans">
                  {result.recommendedAction}
                </p>
                <div className="text-[10px] font-mono text-cyan-400/70 pt-1">
                  * Notice: All agent outputs are defensive and informational. Automated command execution is disabled.
                </div>
              </div>
            </>
          ) : (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">
                  Normalized Event Payload & Correlation Object
                </span>
                <button
                  id="btn-copy-system-raw"
                  onClick={handleCopyRaw}
                  className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono transition-colors"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                      <span className="text-emerald-400">Copied</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy JSON</span>
                    </>
                  )}
                </button>
              </div>

              <pre className="p-4 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 overflow-x-auto max-h-72 leading-relaxed">
                {JSON.stringify(result.rawEvent || result, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <div className="text-[11px] font-mono text-slate-500">
            Dispatched to: Event Correlation Engine (Ready for Stage 5)
          </div>
          <button
            id="btn-dismiss-system-modal"
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
};
