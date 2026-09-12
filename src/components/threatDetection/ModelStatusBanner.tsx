import React from 'react';
import { ShieldCheck, AlertCircle, Info, Cpu, CheckCircle2 } from 'lucide-react';
import { DetectionModelType, ModelStatus } from '../../types/threatDetection';

interface ModelStatusBannerProps {
  activeModelType: DetectionModelType;
  modelStatus: ModelStatus;
  modelName: string;
  onSelectModelType: (type: DetectionModelType) => void;
}

export const ModelStatusBanner: React.FC<ModelStatusBannerProps> = ({
  activeModelType,
  modelStatus,
  modelName,
  onSelectModelType
}) => {
  const getStatusBadge = () => {
    switch (modelStatus) {
      case 'TRAINED':
      case 'CONNECTED':
        return {
          text: 'MODEL STATUS: TRAINED / CONNECTED',
          badgeClass: 'bg-emerald-950 text-emerald-300 border-emerald-700',
          icon: CheckCircle2,
          iconClass: 'text-emerald-400'
        };
      case 'NOT_TRAINED':
        return {
          text: 'MODEL STATUS: NOT TRAINED / TRAINING REQUIRED',
          badgeClass: 'bg-amber-950 text-amber-300 border-amber-700',
          icon: AlertCircle,
          iconClass: 'text-amber-400'
        };
      case 'DEMO':
      default:
        return {
          text: 'MODEL STATUS: DEMO / RULE-BASED / NOT TRAINED',
          badgeClass: 'bg-indigo-950 text-indigo-300 border-indigo-700',
          icon: Info,
          iconClass: 'text-indigo-400'
        };
    }
  };

  const statusBadge = getStatusBadge();
  const StatusIcon = statusBadge.icon;

  return (
    <div className="p-4 bg-slate-900/90 border border-slate-800 rounded-xl space-y-4">
      {/* Top Banner Row */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-slate-800 border border-slate-700 text-cyan-400 shrink-0">
            <Cpu className="w-5 h-5" />
          </div>
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-bold text-white font-mono">{modelName}</h3>
              <span
                id="badge-model-status"
                className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold border flex items-center gap-1.5 ${statusBadge.badgeClass}`}
              >
                <StatusIcon className={`w-3.5 h-3.5 ${statusBadge.iconClass}`} />
                <span>{statusBadge.text}</span>
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Candidate architectures: Supervised Random Forest Classifier & Unsupervised Isolation Forest Anomaly Detector.
            </p>
          </div>
        </div>

        {/* Model Architecture Switcher */}
        <div className="flex items-center gap-1.5 bg-slate-950 p-1 rounded-lg border border-slate-800 self-start md:self-auto">
          <button
            id="btn-model-demo"
            onClick={() => onSelectModelType('RULE_BASED_DEMO')}
            className={`px-2.5 py-1 text-xs font-mono rounded transition-colors ${
              activeModelType === 'RULE_BASED_DEMO'
                ? 'bg-cyan-600 text-white font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Rule-Based Demo
          </button>
          <button
            id="btn-model-rf"
            onClick={() => onSelectModelType('RANDOM_FOREST')}
            className={`px-2.5 py-1 text-xs font-mono rounded transition-colors ${
              activeModelType === 'RANDOM_FOREST'
                ? 'bg-indigo-600 text-white font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Random Forest
          </button>
          <button
            id="btn-model-iforest"
            onClick={() => onSelectModelType('ISOLATION_FOREST')}
            className={`px-2.5 py-1 text-xs font-mono rounded transition-colors ${
              activeModelType === 'ISOLATION_FOREST'
                ? 'bg-purple-600 text-white font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Isolation Forest
          </button>
        </div>
      </div>

      {/* Academic Disclosure & Mode Guidance */}
      <div className="flex items-start gap-2.5 text-xs font-mono text-slate-400 bg-slate-950/60 p-3 rounded-lg border border-slate-800/60">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          {activeModelType === 'RULE_BASED_DEMO' && (
            <span>
              <strong className="text-cyan-300">DEMO DETECTION MODE ACTIVE:</strong> Outputs are produced via deterministic heuristics and verified correlation evidence to showcase pipeline integration. All confidence scores are calculated deterministically and labeled as <strong className="text-cyan-300">DEMO-DERIVED</strong>.
            </span>
          )}
          {activeModelType === 'RANDOM_FOREST' && (
            <span>
              <strong className="text-amber-300">RANDOM FOREST ARCHITECTURE:</strong> Supervised classification requires serialized tree weights or an attached Scikit-Learn Python service. Since no weights are trained in this runtime, the model reports <strong className="text-amber-300">Training Required / Model Not Available</strong> rather than emitting fabricated predictions.
            </span>
          )}
          {activeModelType === 'ISOLATION_FOREST' && (
            <span>
              <strong className="text-purple-300">ISOLATION FOREST ARCHITECTURE:</strong> Unsupervised anomaly scoring requires baseline fitting on benign telemetry. In this environment, status reports <strong className="text-purple-300">Anomaly Model: NOT TRAINED</strong> to preserve empirical academic integrity.
            </span>
          )}
        </div>
      </div>
    </div>
  );
};
