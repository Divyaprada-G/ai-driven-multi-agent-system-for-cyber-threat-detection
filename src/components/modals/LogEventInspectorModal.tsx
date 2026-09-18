import React, { useState } from 'react';
import { LogEvent } from '../../types';
import {
  X,
  Copy,
  Check,
  Download,
  AlertCircle,
  CheckCircle2,
  AlertTriangle,
  Fingerprint,
  Layers,
  Terminal,
  Server,
  Network,
  Globe
} from 'lucide-react';

interface LogEventInspectorModalProps {
  event: LogEvent | null;
  onClose: () => void;
}

export const LogEventInspectorModal: React.FC<LogEventInspectorModalProps> = ({
  event,
  onClose
}) => {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'normalized' | 'raw' | 'diagnostics'>('normalized');

  if (!event) return null;

  const nf = event.normalizedFields || {};
  const validation = event.validation || { status: 'VALID', errors: [], warnings: [] };
  const isValid = validation.status === 'VALID';

  const handleCopyRaw = async () => {
    try {
      await navigator.clipboard.writeText(event.rawData || JSON.stringify(event, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // fallback
    }
  };

  const handleDownloadJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(event, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = `event-${event.id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm overflow-y-auto">
      <div
        id="modal-log-event-inspector"
        className="bg-slate-900 border border-slate-700 rounded-2xl max-w-4xl w-full p-6 shadow-2xl space-y-5 my-8 text-slate-200 animate-in fade-in zoom-in-95 duration-150"
      >
        {/* Header */}
        <div className="flex items-start justify-between pb-4 border-b border-slate-800">
          <div className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs px-2.5 py-1 rounded bg-slate-950 text-cyan-400 border border-cyan-800/60 font-semibold">
                {event.id}
              </span>

              {/* LogType Badge */}
              <span
                className={`px-2.5 py-0.5 rounded text-xs font-mono font-semibold border ${
                  event.logType === 'NETWORK'
                    ? 'bg-blue-950/60 text-blue-400 border-blue-800'
                    : event.logType === 'SYSTEM'
                    ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                    : 'bg-purple-950/60 text-purple-400 border-purple-800'
                }`}
              >
                {event.logType} DOMAIN
              </span>

              {/* Validation Status */}
              <span
                className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-mono font-semibold border ${
                  isValid
                    ? 'bg-emerald-950/50 text-emerald-400 border-emerald-800/80'
                    : 'bg-rose-950/50 text-rose-400 border-rose-800/80'
                }`}
              >
                {isValid ? <CheckCircle2 className="w-3.5 h-3.5" /> : <AlertCircle className="w-3.5 h-3.5" />}
                {isValid ? 'SCHEMA VALID' : 'SCHEMA INVALID'}
              </span>

              {/* Duplicate Badge */}
              {event.isDuplicate && (
                <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded text-xs font-mono font-semibold bg-amber-950/60 text-amber-400 border border-amber-800">
                  <Fingerprint className="w-3.5 h-3.5" />
                  DUPLICATE #{event.duplicateCount || 2}
                </span>
              )}

              {event.format && (
                <span className="px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-400 border border-slate-700">
                  {event.format}
                </span>
              )}
            </div>

            <h2 className="text-base sm:text-lg font-bold text-white tracking-tight pt-2">
              {event.message}
            </h2>
            <p className="text-xs text-slate-400 font-mono">
              Timestamp: {event.timestamp} • Origin Source: <span className="text-cyan-400">{event.source}</span>
            </p>
          </div>

          <button
            id="btn-close-event-modal"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div className="flex items-center gap-2">
            <button
              id="tab-btn-normalized"
              onClick={() => setActiveTab('normalized')}
              className={`px-3 py-1.5 text-xs font-mono rounded-lg transition-colors flex items-center gap-1.5 ${
                activeTab === 'normalized'
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50 font-bold'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Layers className="w-3.5 h-3.5" />
              Normalized Fields
            </button>

            <button
              id="tab-btn-raw"
              onClick={() => setActiveTab('raw')}
              className={`px-3 py-1.5 text-xs font-mono rounded-lg transition-colors flex items-center gap-1.5 ${
                activeTab === 'raw'
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50 font-bold'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <Terminal className="w-3.5 h-3.5" />
              Raw Log Stream
            </button>

            <button
              id="tab-btn-diagnostics"
              onClick={() => setActiveTab('diagnostics')}
              className={`px-3 py-1.5 text-xs font-mono rounded-lg transition-colors flex items-center gap-1.5 ${
                activeTab === 'diagnostics'
                  ? 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/50 font-bold'
                  : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
              }`}
            >
              <AlertCircle className="w-3.5 h-3.5" />
              Validation Diagnostics ({validation.errors.length + validation.warnings.length})
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              id="btn-copy-raw-payload"
              onClick={handleCopyRaw}
              className="px-2.5 py-1 text-xs font-mono rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1.5 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied' : 'Copy'}
            </button>
            <button
              id="btn-export-single-event"
              onClick={handleDownloadJson}
              className="px-2.5 py-1 text-xs font-mono rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1.5 transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Export JSON
            </button>
          </div>
        </div>

        {/* Tab 1: Normalized Attributes */}
        {activeTab === 'normalized' && (
          <div className="space-y-4">
            {/* Domain Field Grid */}
            <div className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-3">
              <div className="flex items-center gap-2 text-xs font-mono text-cyan-400 font-semibold uppercase tracking-wider">
                {event.logType === 'NETWORK' && <Network className="w-4 h-4" />}
                {event.logType === 'SYSTEM' && <Server className="w-4 h-4" />}
                {event.logType === 'APPLICATION' && <Globe className="w-4 h-4" />}
                <span>Standardized {event.logType} Attributes</span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs font-mono">
                {event.logType === 'NETWORK' && (
                  <>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Source Socket</span>
                      <span className="text-slate-200 font-semibold">{nf.sourceIp || 'N/A'}{nf.sourcePort ? `:${nf.sourcePort}` : ''}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Destination Socket</span>
                      <span className="text-slate-200 font-semibold">{nf.destinationIp || 'N/A'}{nf.destinationPort ? `:${nf.destinationPort}` : ''}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Protocol</span>
                      <span className="text-cyan-400 font-bold">{nf.protocol || 'TCP'}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Flags</span>
                      <span className="text-amber-400">{nf.flags ? (Array.isArray(nf.flags) ? nf.flags.join(', ') : nf.flags) : 'N/A'}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Packet Length</span>
                      <span className="text-slate-200">{nf.packetSize ? `${nf.packetSize} bytes` : 'N/A'}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Flow Duration</span>
                      <span className="text-slate-200">{nf.flowDuration ? `${nf.flowDuration} ms` : 'N/A'}</span>
                    </div>
                  </>
                )}

                {event.logType === 'SYSTEM' && (
                  <>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Host Name</span>
                      <span className="text-slate-200 font-semibold">{nf.hostName || 'N/A'}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Process Name</span>
                      <span className="text-cyan-400 font-bold">{nf.processName || 'N/A'}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Process ID (PID)</span>
                      <span className="text-slate-200">{nf.processId || 'N/A'}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">User Account</span>
                      <span className="text-amber-300">{nf.userName || 'N/A'}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Parent Process</span>
                      <span className="text-slate-300">{nf.parentProcess || 'N/A'}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Integrity / Token</span>
                      <span className="text-rose-400">{nf.integrityLevel || 'Normal'}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 sm:col-span-3">
                      <span className="text-slate-500 block text-[10px] uppercase">Command Line</span>
                      <span className="text-emerald-400 break-all">{nf.commandLine || 'N/A'}</span>
                    </div>
                  </>
                )}

                {event.logType === 'APPLICATION' && (
                  <>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">HTTP Method</span>
                      <span className="text-cyan-400 font-bold">{nf.httpMethod || 'GET'}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Endpoint URI</span>
                      <span className="text-slate-200 font-mono break-all">{nf.endpoint || '/'}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Response Status</span>
                      <span className={`font-bold ${Number(nf.statusCode) >= 400 ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {nf.statusCode || 200}
                      </span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 sm:col-span-2">
                      <span className="text-slate-500 block text-[10px] uppercase">User Agent</span>
                      <span className="text-slate-300 truncate block">{nf.userAgent || 'N/A'}</span>
                    </div>
                    <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800">
                      <span className="text-slate-500 block text-[10px] uppercase">Application / Service</span>
                      <span className="text-purple-300">{nf.applicationName || 'Web Gateway'}</span>
                    </div>
                    {nf.payloadSnippet && (
                      <div className="p-2.5 bg-slate-900 rounded-lg border border-slate-800 sm:col-span-3">
                        <span className="text-slate-500 block text-[10px] uppercase">Payload / Query Body</span>
                        <span className="text-amber-300 font-mono break-all">{nf.payloadSnippet}</span>
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>

            {/* Ingestion & Fingerprint Metadata */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl space-y-1">
                <span className="text-slate-500 text-[11px] block">Deterministic Event Fingerprint</span>
                <span className="text-slate-300 font-mono text-xs break-all">{event.fingerprint || 'N/A'}</span>
              </div>
              <div className="p-3 bg-slate-950/60 border border-slate-800 rounded-xl space-y-1">
                <span className="text-slate-500 text-[11px] block">Pipeline Ingestion Timestamp</span>
                <span className="text-slate-300 font-mono text-xs">{event.ingestionTimestamp || 'Live Ingestion'}</span>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Raw Log Data */}
        {activeTab === 'raw' && (
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs font-mono text-slate-400">
              <span>Raw Telemetry String (Untrusted Input Buffer)</span>
              <span>Length: {event.rawData?.length || 0} bytes</span>
            </div>
            <div className="p-4 bg-black/90 rounded-xl border border-slate-800 font-mono text-xs text-emerald-400 overflow-x-auto max-h-72 leading-relaxed whitespace-pre-wrap break-all select-all">
              {event.rawData || JSON.stringify(event, null, 2)}
            </div>
          </div>
        )}

        {/* Tab 3: Validation Diagnostics */}
        {activeTab === 'diagnostics' && (
          <div className="space-y-4">
            <div className="p-4 bg-slate-950 border border-slate-800 rounded-xl space-y-3">
              <div className="flex items-center gap-2">
                {isValid ? (
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                ) : (
                  <AlertCircle className="w-5 h-5 text-rose-400" />
                )}
                <div>
                  <h4 className="text-sm font-bold text-white font-mono">
                    Validation State: {isValid ? 'PASSED (0 Schema Errors)' : `${validation.errors.length} Critical Syntax Error(s)`}
                  </h4>
                  <p className="text-xs text-slate-400">
                    Validated against RFC specs, IPv4/IPv6 address syntax, port ranges (0-65535), and domain type models.
                  </p>
                </div>
              </div>

              {/* Errors */}
              {(validation.errors?.length > 0 || (validation.structured?.errors && validation.structured.errors.length > 0)) && (
                <div className="space-y-1.5 pt-2">
                  <span className="text-xs font-mono font-bold text-rose-400 uppercase tracking-wider block">
                    Errors ({validation.structured?.errors?.length || validation.errors?.length || 0})
                  </span>
                  {validation.structured?.errors && validation.structured.errors.length > 0 ? (
                    validation.structured.errors.map((err, idx) => (
                      <div key={idx} className="p-2.5 rounded-lg bg-rose-950/40 border border-rose-900/50 text-xs font-mono text-rose-300 flex flex-col gap-1">
                        <div className="flex items-center gap-2">
                          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                          <span className="font-bold text-rose-200">[{err.code}]</span>
                          <span className="text-slate-400">Field: {err.field}</span>
                          {err.originalValue !== undefined && (
                            <span className="text-amber-400 text-[11px] bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                              Value: {String(err.originalValue)}
                            </span>
                          )}
                        </div>
                        <span className="pl-6 text-slate-300">{err.message}</span>
                      </div>
                    ))
                  ) : (
                    validation.errors.map((err: any, idx: number) => {
                      const text = typeof err === 'string' ? err : `${err.code || ''}: ${err.message || JSON.stringify(err)}`;
                      return (
                        <div key={idx} className="p-2.5 rounded-lg bg-rose-950/40 border border-rose-900/50 text-xs font-mono text-rose-300 flex items-start gap-2">
                          <AlertCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                          <span>{text}</span>
                        </div>
                      );
                    })
                  )}
                </div>
              )}

              {/* Warnings */}
              {(validation.warnings?.length > 0 || (validation.structured?.warnings && validation.structured.warnings.length > 0)) && (
                <div className="space-y-1.5 pt-2">
                  <span className="text-xs font-mono font-bold text-amber-400 uppercase tracking-wider block">
                    Warnings ({validation.structured?.warnings?.length || validation.warnings?.length || 0})
                  </span>
                  {validation.warnings.map((warn: any, idx: number) => {
                    const text = typeof warn === 'string' ? warn : `${warn.code || ''}: ${warn.message || JSON.stringify(warn)}`;
                    return (
                      <div key={idx} className="p-2.5 rounded-lg bg-amber-950/40 border border-amber-900/50 text-xs font-mono text-amber-300 flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
                        <span>{text}</span>
                      </div>
                    );
                  })}
                </div>
              )}

              {isValid && validation.warnings.length === 0 && (
                <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-900/40 text-xs font-mono text-emerald-300 flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>All fields strictly conform to SOC telemetry specifications with valid timestamp, socket parameters, and identity attributes.</span>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="flex items-center justify-between pt-4 border-t border-slate-800 text-xs font-mono text-slate-400">
          <span>Target Processing Pipeline: {event.logType}_AGENT</span>
          <button
            onClick={onClose}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white transition-colors"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
