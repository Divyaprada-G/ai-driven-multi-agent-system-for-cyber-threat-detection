import React from 'react';
import {
  Database,
  Cpu,
  Layers,
  CheckCircle2,
  AlertTriangle,
  ExternalLink,
  Shield,
  Activity,
  Sliders,
  Sparkles
} from 'lucide-react';
import { mlTrainingService } from '../../services/mlTrainingService';
import { TrainedModelArtifact } from '../../types/datasetMl';

interface ModelInfoPanelProps {
  onNavigateToTraining: () => void;
}

export const ModelInfoPanel: React.FC<ModelInfoPanelProps> = ({ onNavigateToTraining }) => {
  const activeModel: TrainedModelArtifact | null = mlTrainingService.getActiveModel();

  if (!activeModel) {
    return (
      <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 text-center">
        <AlertTriangle className="w-8 h-8 text-amber-500 mx-auto mb-2" />
        <h4 className="text-sm font-bold text-slate-200">No Model Registered</h4>
        <p className="text-xs text-slate-400 mt-1">Train a real model in Datasets & ML Training first.</p>
        <button
          onClick={onNavigateToTraining}
          className="mt-3 px-3 py-1.5 rounded-lg bg-sky-500/20 text-sky-300 border border-sky-500/30 text-xs font-semibold hover:bg-sky-500/30 transition-colors"
        >
          Open Model Training
        </button>
      </div>
    );
  }

  const isRF = activeModel.modelType === 'RANDOM_FOREST';

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-4 shadow-sm">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center space-x-2.5">
          <div className="p-2 rounded-lg bg-sky-500/10 text-sky-400">
            <Cpu className="w-4 h-4" />
          </div>
          <div>
            <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider">Active ML Inference Model</h3>
            <p className="text-[11px] text-slate-400">{activeModel.modelId} ({activeModel.modelVersion})</p>
          </div>
        </div>
        <button
          onClick={onNavigateToTraining}
          className="px-2.5 py-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-sky-400 text-xs font-medium inline-flex items-center space-x-1 transition-colors"
        >
          <span>Training Details</span>
          <ExternalLink className="w-3 h-3" />
        </button>
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
          <span className="text-[10px] text-slate-500 block">Algorithm</span>
          <span className="font-bold text-slate-200">{isRF ? 'Random Forest' : 'Isolation Forest'}</span>
        </div>
        <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
          <span className="text-[10px] text-slate-500 block">Status</span>
          <span className={`font-semibold ${
            activeModel.modelStatus === 'TRAINED' ? 'text-emerald-400' : 'text-indigo-300'
          }`}>
            {activeModel.modelStatus}
          </span>
        </div>
        <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
          <span className="text-[10px] text-slate-500 block">Training Dataset</span>
          <span className="font-mono text-slate-200 text-[11px] truncate block">{activeModel.datasetName}</span>
        </div>
        <div className="bg-slate-950/60 p-2.5 rounded-lg border border-slate-800/80">
          <span className="text-[10px] text-slate-500 block">Features Evaluated</span>
          <span className="font-bold text-sky-400">{activeModel.featureCount} Numerical Columns</span>
        </div>
      </div>

      {/* Target Classes */}
      <div>
        <span className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider block mb-1.5">
          Learned Target Classes:
        </span>
        <div className="flex flex-wrap gap-1">
          {activeModel.classLabels.map((c) => (
            <span
              key={c}
              className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                c === 'BENIGN'
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  : 'bg-rose-500/10 text-rose-400 border border-rose-500/20'
              }`}
            >
              {c}
            </span>
          ))}
        </div>
      </div>

      {/* Isolation Forest Anomaly Detection Section */}
      <div className="bg-slate-950/80 border border-slate-800/80 rounded-lg p-3 text-xs space-y-1">
        <div className="flex items-center justify-between">
          <span className="font-semibold text-slate-300 flex items-center space-x-1.5">
            <Activity className="w-3.5 h-3.5 text-cyan-400" />
            <span>Isolation Forest Anomaly Layer:</span>
          </span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono">
            ACTIVE
          </span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          Isolation Forest anomaly scores (-1 outlier / 1 normal) are evaluated independently from Random Forest classification probabilities to detect novel zero-day attack drifts without conflation.
        </p>
      </div>
    </div>
  );
};
