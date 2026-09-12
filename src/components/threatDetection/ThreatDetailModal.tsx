import React from 'react';
import { X, ShieldAlert, Cpu, CheckCircle2, ArrowRight, ExternalLink, Activity, Info } from 'lucide-react';
import { ThreatDetectionResult } from '../../types/threatDetection';

interface ThreatDetailModalProps {
  detection: ThreatDetectionResult | null;
  onClose: () => void;
  onViewCorrelation?: (correlationId: string) => void;
}

export const ThreatDetailModal: React.FC<ThreatDetailModalProps> = ({
  detection,
  onClose,
  onViewCorrelation
}) => {
  if (!detection) return null;

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-950 text-rose-300 border-rose-800';
      case 'HIGH':
        return 'bg-orange-950 text-orange-300 border-orange-800';
      case 'MEDIUM':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'LOW':
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div
      role="dialog"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200"
    >
      <div
        className="bg-slate-900 border border-slate-800 rounded-xl max-w-3xl w-full max-h-[90vh] overflow-hidden flex flex-col shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="p-4 bg-slate-950 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-mono text-cyan-400 font-bold">{detection.id}</span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${getSeverityBadge(detection.severity)}`}>
                  {detection.severity}
                </span>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-950 text-indigo-300 border border-indigo-800">
                  {detection.modelStatus}
                </span>
              </div>
              <h3 className="text-base font-bold text-white font-mono mt-0.5">
                {detection.classification}
              </h3>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 overflow-y-auto space-y-4 text-xs font-mono">
          {/* Key Metrics Row */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Model Confidence</span>
              <span className="text-lg font-bold text-cyan-400">
                {(detection.confidence * 100).toFixed(1)}%
              </span>
              <span className="text-[9px] text-slate-400 block mt-0.5">
                {detection.confidenceType}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Anomaly Score</span>
              <span className="text-lg font-bold text-rose-400">
                {detection.anomalyScore.toFixed(3)}
              </span>
              <span className="text-[9px] text-slate-400 block mt-0.5">
                {detection.anomalyScoreLabel}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Correlation ID</span>
              <span className="text-xs font-bold text-indigo-300 truncate block mt-1">
                {detection.correlationId}
              </span>
              <span className="text-[9px] text-slate-500 block">Upstream Cluster</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Participating Agents</span>
              <span className="text-sm font-bold text-emerald-400 block mt-1">
                {detection.features.participatingAgentsCount} Agent(s)
              </span>
              <span className="text-[9px] text-slate-500 block">
                {detection.explanation.participatingAgents.join(', ') || 'Correlated'}
              </span>
            </div>
          </div>

          {/* Explainable AI Section */}
          <div className="p-4 bg-slate-950 rounded-lg border border-cyan-900/40 space-y-3">
            <div className="flex items-center gap-1.5 text-cyan-300 font-bold">
              <Cpu className="w-4 h-4 text-cyan-400" />
              <span>Explainable AI Attribution & Reasoning</span>
            </div>

            <div className="space-y-2 text-slate-300 leading-relaxed">
              <p>
                <strong className="text-white">Why Analyzed: </strong>
                {detection.explanation.whyAnalyzed}
              </p>
            </div>

            {/* Contributing Features Table */}
            {detection.explanation.contributingFeatures && detection.explanation.contributingFeatures.length > 0 && (
              <div className="space-y-1.5 pt-2 border-t border-slate-800/80">
                <span className="text-[11px] text-slate-400 font-bold block">Top Contributing Feature Signals:</span>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {detection.explanation.contributingFeatures.map((feat, idx) => (
                    <div
                      key={idx}
                      className="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between text-[11px]"
                    >
                      <span className="text-slate-400">{feat.feature}:</span>
                      <div className="flex items-center gap-2">
                        <span className="text-slate-200 font-bold">{String(feat.value)}</span>
                        <span
                          className={`px-1.5 py-0.2 text-[9px] rounded font-bold ${
                            feat.impact === 'HIGH'
                              ? 'bg-rose-950 text-rose-300 border border-rose-800'
                              : 'bg-amber-950 text-amber-300 border border-amber-800'
                          }`}
                        >
                          {feat.impact}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Supporting Evidence List */}
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
            <span className="text-slate-300 font-bold block">Supporting Telemetry Evidence:</span>
            <ul className="space-y-1 text-slate-400 text-[11px]">
              {detection.evidence.map((ev, i) => (
                <li key={i} className="flex items-start gap-1.5">
                  <span className="text-cyan-400 mt-0.5">•</span>
                  <span>{ev}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* 18-Dimensional Feature Vector Matrix */}
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
            <span className="text-slate-300 font-bold block">18-Dimensional Extracted Feature Vector:</span>
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 text-[10px]">
              {Object.entries(detection.features).map(([key, val]) => (
                <div key={key} className="p-1.5 rounded bg-slate-900 border border-slate-800/80 flex justify-between">
                  <span className="text-slate-400 truncate mr-1">{key}:</span>
                  <span className="text-cyan-300 font-bold">{String(val)}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Recommended Action */}
          <div className="p-3 bg-indigo-950/40 rounded-lg border border-indigo-800/50 space-y-1">
            <span className="text-indigo-300 font-bold flex items-center gap-1.5">
              <Info className="w-3.5 h-3.5" />
              Recommended Containment / Analyst Action:
            </span>
            <p className="text-slate-300 text-[11px]">
              {detection.recommendedAction}
            </p>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-4 bg-slate-950 border-t border-slate-800 flex items-center justify-between">
          <div className="text-[11px] font-mono text-slate-500">
            Model: {detection.model}
          </div>
          <div className="flex items-center gap-2">
            {onViewCorrelation && (
              <button
                id="btn-view-correlated-event"
                onClick={() => onViewCorrelation(detection.correlationId)}
                className="px-3 py-1.5 bg-indigo-900 hover:bg-indigo-800 text-indigo-200 rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-colors border border-indigo-700"
              >
                <span>View Correlated Event</span>
                <ExternalLink className="w-3.5 h-3.5" />
              </button>
            )}
            <button
              onClick={onClose}
              className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono transition-colors"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
