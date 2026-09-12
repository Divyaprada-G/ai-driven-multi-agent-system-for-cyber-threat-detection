import React, { useState } from 'react';
import { NetworkAgentResult } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import {
  X,
  ShieldAlert,
  Activity,
  ArrowRight,
  Terminal,
  Copy,
  Check,
  CheckCircle2,
  AlertTriangle,
  Lightbulb,
  FileCode
} from 'lucide-react';

interface NetworkDetailModalProps {
  result: NetworkAgentResult | null;
  onClose: () => void;
}

export const NetworkDetailModal: React.FC<NetworkDetailModalProps> = ({
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
      id="modal-network-detail"
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
              <span className="text-xs font-mono text-cyan-400 font-semibold uppercase tracking-wider">
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
            id="btn-close-network-modal"
            onClick={onClose}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Visual 3-Step Detection Pipeline Flow */}
        <div className="p-4 bg-slate-950/60 border-b border-slate-800">
          <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400 mb-2 font-semibold">
            Explainable Detection Reasoning Path
          </div>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs font-mono">
            {/* Step 1 */}
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
              <div className="text-cyan-400 font-bold flex items-center gap-1.5">
                <span className="w-4 h-4 rounded-full bg-cyan-950 border border-cyan-800 text-[10px] flex items-center justify-center">
                  1
                </span>
                <span>Observed Activity</span>
              </div>
              <p className="text-slate-300 font-sans text-xs leading-relaxed">
                {result.observedActivity}
              </p>
            </div>

            {/* Step 2 */}
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
              <div className="text-amber-400 font-bold flex items-center gap-1.5">
                <span className="w-4 h-4 rounded-full bg-amber-950 border border-amber-800 text-[10px] flex items-center justify-center">
                  2
                </span>
                <span>Detected Pattern</span>
              </div>
              <p className="text-slate-300 font-sans text-xs leading-relaxed">
                {result.detectedPattern}
              </p>
            </div>

            {/* Step 3 */}
            <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 space-y-1">
              <div className="text-rose-400 font-bold flex items-center gap-1.5">
                <span className="w-4 h-4 rounded-full bg-rose-950 border border-rose-800 text-[10px] flex items-center justify-center">
                  3
                </span>
                <span>Security Finding</span>
              </div>
              <p className="text-slate-300 font-sans text-xs leading-relaxed">
                {result.securityFinding}
              </p>
            </div>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-5 space-y-5 max-h-[60vh] overflow-y-auto">
          {/* Key Attributes Grid */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950/80 p-3.5 rounded-lg border border-slate-800 text-xs font-mono">
            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Source Endpoint</span>
              <span className="text-white font-bold">{result.sourceIp}</span>
              {result.sourcePort && (
                <span className="text-slate-400 block text-[11px]">Port: {result.sourcePort}</span>
              )}
            </div>

            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Destination Endpoint</span>
              <span className="text-white font-bold">{result.destinationIp}</span>
              {result.destinationPort && (
                <span className="text-slate-400 block text-[11px]">Port: {result.destinationPort}</span>
              )}
            </div>

            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Protocol & Ports</span>
              <span className="text-cyan-400 font-bold">{result.protocol || 'TCP'}</span>
              <span className="text-slate-400 block text-[11px]">
                {result.ports && result.ports.length > 1
                  ? `${result.ports.length} ports probed`
                  : result.destinationPort ? `Port ${result.destinationPort}` : 'All Ports'}
              </span>
            </div>

            <div>
              <span className="text-slate-500 block text-[10px] uppercase">Timestamp</span>
              <span className="text-slate-300">
                {result.timestamp ? result.timestamp.replace('T', ' ').substring(0, 19) : '-'}
              </span>
            </div>
          </div>

          {/* Observed Ports List (if multi-port scan) */}
          {result.ports && result.ports.length > 1 && (
            <div className="space-y-1.5">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider font-semibold">
                Probed Destination Ports ({result.ports.length})
              </span>
              <div className="flex flex-wrap gap-1.5 p-3 rounded-lg bg-slate-950/70 border border-slate-800 max-h-28 overflow-y-auto font-mono text-xs">
                {result.ports.map(p => (
                  <span
                    key={p}
                    className="px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300"
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Tabs: Evidence vs Raw Log */}
          <div className="border-b border-slate-800 flex items-center gap-4 text-xs font-mono">
            <button
              id="tab-btn-evidence"
              onClick={() => setTab('evidence')}
              className={`pb-2 border-b-2 transition-colors ${
                tab === 'evidence'
                  ? 'border-cyan-400 text-cyan-400 font-bold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Observable Evidence & Indicators ({result.evidence.length})
            </button>
            <button
              id="tab-btn-raw"
              onClick={() => setTab('raw')}
              className={`pb-2 border-b-2 transition-colors ${
                tab === 'raw'
                  ? 'border-cyan-400 text-cyan-400 font-bold'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              Raw Event Payload
            </button>
          </div>

          {tab === 'evidence' ? (
            <div className="space-y-4">
              {/* Evidence Points */}
              <div className="space-y-2">
                <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider font-semibold">
                  Why this detection was generated:
                </h4>
                <div className="space-y-1.5">
                  {result.evidence.map((point, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/90 text-xs text-slate-200 font-mono flex items-start gap-2"
                    >
                      <span className="text-cyan-400 font-bold mt-0.5">•</span>
                      <span>{point}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Indicators */}
              {result.indicators && result.indicators.length > 0 && (
                <div className="space-y-2">
                  <h4 className="text-xs font-mono text-slate-400 uppercase tracking-wider font-semibold">
                    Telemetry Indicators:
                  </h4>
                  <div className="flex flex-wrap gap-1.5">
                    {result.indicators.map((ind, i) => (
                      <span
                        key={i}
                        className="px-2.5 py-1 rounded bg-slate-800/80 border border-slate-700 text-xs font-mono text-slate-300"
                      >
                        {ind}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Defensive Recommended Action */}
              <div className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-800/50 space-y-1.5">
                <div className="flex items-center gap-2 text-xs font-bold text-amber-400 font-mono">
                  <Lightbulb className="w-4 h-4" />
                  <span>Defensive SOC Recommendation (Informational)</span>
                </div>
                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {result.recommendedAction}
                </p>
                <p className="text-[11px] text-slate-500 font-mono italic">
                  Defensive guidelines only. The system does not execute disruptive commands or automatic blocking.
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono text-slate-400">JSON Representation</span>
                <button
                  id="btn-copy-raw-json"
                  onClick={handleCopyRaw}
                  className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 font-mono"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  <span>{copied ? 'Copied' : 'Copy JSON'}</span>
                </button>
              </div>
              <pre className="p-3 rounded-lg bg-black/80 border border-slate-800 text-[11px] text-emerald-400 font-mono overflow-x-auto max-h-60">
                {JSON.stringify(result.rawEvent || result, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between text-xs font-mono text-slate-400">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span>Agent Status: DISPATCHED_TO_CORRELATION</span>
          </div>
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
