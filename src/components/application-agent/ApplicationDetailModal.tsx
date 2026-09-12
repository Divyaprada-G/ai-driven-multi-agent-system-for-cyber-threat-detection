import React, { useState } from 'react';
import {
  X,
  ShieldAlert,
  CheckCircle2,
  Copy,
  Check,
  Search,
  Cpu,
  FileCode,
  Info,
  Server,
  User,
  Globe
} from 'lucide-react';
import { ApplicationAgentResult } from '../../types/application';

interface Props {
  result: ApplicationAgentResult | null;
  onClose: () => void;
}

export const ApplicationDetailModal: React.FC<Props> = ({ result, onClose }) => {
  const [copied, setCopied] = useState(false);
  const [activeTab, setActiveTab] = useState<'reasoning' | 'evidence' | 'payload'>('reasoning');

  if (!result) return null;

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(result, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getSeverityBadge = (severity: string) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300 border-rose-300 dark:border-rose-800';
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-950/60 dark:text-orange-300 border-orange-300 dark:border-orange-800';
      case 'MEDIUM':
        return 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 border-amber-300 dark:border-amber-800';
      default:
        return 'bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300 border-blue-300 dark:border-blue-800';
    }
  };

  const getStatusBadge = (code?: number) => {
    if (!code) return 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300';
    if (code >= 200 && code < 300) return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300';
    if (code >= 300 && code < 400) return 'bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300';
    if (code === 401 || code === 403) return 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300';
    if (code >= 400 && code < 500) return 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300';
    return 'bg-red-100 text-red-800 dark:bg-red-950/60 dark:text-red-300';
  };

  return (
    <div
      id="application-detail-modal-backdrop"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/60 backdrop-blur-sm animate-in fade-in duration-200"
      onClick={e => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        id="application-detail-modal-card"
        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-2xl w-full max-w-4xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden animate-in zoom-in-95 duration-200"
      >
        {/* Modal Header */}
        <div className="px-6 py-5 border-b border-slate-200 dark:border-slate-800 flex items-start justify-between bg-slate-50/50 dark:bg-slate-800/30">
          <div className="space-y-1.5 pr-4">
            <div className="flex flex-wrap items-center gap-2">
              <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold border ${getSeverityBadge(result.severity)}`}>
                {result.severity}
              </span>
              <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700">
                Confidence: {Math.round(result.confidence * 100)}%
              </span>
              <span className={`px-2 py-0.5 rounded text-xs font-mono font-semibold ${getStatusBadge(result.statusCode)}`}>
                {result.method || 'REQ'} {result.statusCode ? `HTTP ${result.statusCode}` : ''}
              </span>
              <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                {result.timestamp}
              </span>
            </div>
            <h2 className="text-lg font-bold text-slate-900 dark:text-slate-100">
              {result.detection}
            </h2>
            <div className="flex flex-wrap items-center gap-4 text-xs text-slate-600 dark:text-slate-400">
              <span className="flex items-center gap-1 font-mono">
                <Globe className="w-3.5 h-3.5 text-slate-400" />
                {result.endpoint || '/'}
              </span>
              {result.sourceIp && (
                <span className="flex items-center gap-1 font-mono">
                  <Server className="w-3.5 h-3.5 text-slate-400" />
                  Client: {result.sourceIp}
                </span>
              )}
              {result.username && (
                <span className="flex items-center gap-1 font-mono">
                  <User className="w-3.5 h-3.5 text-slate-400" />
                  User: {result.username}
                </span>
              )}
            </div>
          </div>
          <button
            id="close-application-modal-btn"
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Navigation Sub-tabs */}
        <div className="flex border-b border-slate-200 dark:border-slate-800 px-6 bg-slate-50/30 dark:bg-slate-900">
          <button
            id="tab-reasoning-btn"
            onClick={() => setActiveTab('reasoning')}
            className={`py-3 px-4 text-xs font-semibold border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'reasoning'
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
            }`}
          >
            <Cpu className="w-4 h-4" />
            3-Step Reasoning Path
          </button>
          <button
            id="tab-evidence-btn"
            onClick={() => setActiveTab('evidence')}
            className={`py-3 px-4 text-xs font-semibold border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'evidence'
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
            }`}
          >
            <Search className="w-4 h-4" />
            Forensic Evidence & Indicators
          </button>
          <button
            id="tab-payload-btn"
            onClick={() => setActiveTab('payload')}
            className={`py-3 px-4 text-xs font-semibold border-b-2 flex items-center gap-2 transition-colors ${
              activeTab === 'payload'
                ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400'
                : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
            }`}
          >
            <FileCode className="w-4 h-4" />
            Correlation Contract & Raw Log
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 text-sm flex-1">
          {activeTab === 'reasoning' && (
            <div className="space-y-4">
              {/* Step 1: Observed Activity */}
              <div className="p-4 rounded-xl border border-blue-200 dark:border-blue-900/50 bg-blue-50/50 dark:bg-blue-950/20 space-y-2">
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-blue-700 dark:text-blue-300">
                  <span className="w-5 h-5 rounded-full bg-blue-600 text-white flex items-center justify-center text-[10px]">
                    1
                  </span>
                  Step 1: Observed Telemetry
                </div>
                <p className="text-slate-800 dark:text-slate-200 leading-relaxed font-medium">
                  {result.observedActivity}
                </p>
              </div>

              {/* Step 2: Detected Pattern */}
              <div className="p-4 rounded-xl border border-amber-200 dark:border-amber-900/50 bg-amber-50/50 dark:bg-amber-950/20 space-y-2">
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-amber-700 dark:text-amber-300">
                  <span className="w-5 h-5 rounded-full bg-amber-600 text-white flex items-center justify-center text-[10px]">
                    2
                  </span>
                  Step 2: Behavioral Pattern Recognition
                </div>
                <p className="text-slate-800 dark:text-slate-200 leading-relaxed font-medium">
                  {result.detectedPattern}
                </p>
              </div>

              {/* Step 3: Security Assessment */}
              <div className="p-4 rounded-xl border border-rose-200 dark:border-rose-900/50 bg-rose-50/50 dark:bg-rose-950/20 space-y-2">
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-rose-700 dark:text-rose-300">
                  <span className="w-5 h-5 rounded-full bg-rose-600 text-white flex items-center justify-center text-[10px]">
                    3
                  </span>
                  Step 3: Security Assessment & Impact
                </div>
                <p className="text-slate-800 dark:text-slate-200 leading-relaxed font-medium">
                  {result.securityFinding}
                </p>
              </div>

              {/* Defensive Advisory Recommendation */}
              <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/40 space-y-2">
                <div className="flex items-center gap-2 text-xs font-bold text-slate-700 dark:text-slate-300">
                  <Info className="w-4 h-4 text-indigo-500" />
                  Recommended Operational Action (Informational Advisory Only)
                </div>
                <p className="text-slate-700 dark:text-slate-300 text-xs leading-relaxed">
                  {result.recommendedAction}
                </p>
              </div>
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="space-y-5">
              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
                  Observable Forensic Evidence Statements
                </h4>
                <ul className="space-y-2">
                  {result.evidence.map((item, idx) => (
                    <li
                      key={idx}
                      className="flex items-start gap-2.5 p-3 rounded-lg bg-slate-50 dark:bg-slate-800/50 border border-slate-200 dark:border-slate-750 font-mono text-xs text-slate-800 dark:text-slate-200"
                    >
                      <CheckCircle2 className="w-4 h-4 text-indigo-500 shrink-0 mt-0.5" />
                      <span>{item}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 dark:text-slate-400 mb-2">
                  Observed Indicators & Tags
                </h4>
                <div className="flex flex-wrap gap-2">
                  {result.indicators.map((ind, idx) => (
                    <span
                      key={idx}
                      className="px-2.5 py-1 rounded-md text-xs font-semibold bg-indigo-50 dark:bg-indigo-950/50 text-indigo-700 dark:text-indigo-300 border border-indigo-200 dark:border-indigo-900/50"
                    >
                      #{ind}
                    </span>
                  ))}
                </div>
              </div>

              {result.userAgent && (
                <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/30">
                  <div className="text-xs font-bold text-slate-600 dark:text-slate-400 mb-1">
                    HTTP User-Agent Header
                  </div>
                  <div className="font-mono text-xs text-slate-800 dark:text-slate-200 break-all">
                    {result.userAgent}
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'payload' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-slate-500 dark:text-slate-400 uppercase tracking-wider">
                  Correlation Contract JSON Representation
                </span>
                <button
                  id="copy-payload-json-btn"
                  onClick={handleCopyJson}
                  className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-900 flex items-center gap-1.5 hover:bg-indigo-100 dark:hover:bg-indigo-900 transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-500" /> : <Copy className="w-3.5 h-3.5" />}
                  {copied ? 'Copied to Clipboard' : 'Copy JSON'}
                </button>
              </div>
              <pre className="p-4 rounded-xl bg-slate-950 text-slate-100 text-xs font-mono overflow-x-auto border border-slate-800 leading-relaxed max-h-96">
                {JSON.stringify(result, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-4 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between bg-slate-50 dark:bg-slate-900">
          <span className="text-xs text-slate-500 dark:text-slate-400">
            Event ID: <span className="font-mono">{result.eventId}</span>
          </span>
          <button
            id="close-modal-footer-btn"
            onClick={onClose}
            className="px-4 py-2 text-xs font-semibold rounded-xl bg-slate-800 dark:bg-slate-200 text-white dark:text-slate-900 hover:bg-slate-700 dark:hover:bg-slate-300 transition-colors"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
};
