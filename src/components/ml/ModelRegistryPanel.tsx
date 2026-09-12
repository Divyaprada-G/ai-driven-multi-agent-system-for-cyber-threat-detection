import React, { useState } from 'react';
import {
  FolderGit2,
  CheckCircle,
  Clock,
  Layers,
  Sparkles,
  ArrowRight,
  Shield,
  FileText,
  Activity,
  TreePine
} from 'lucide-react';
import { TrainedModelArtifact } from '../../types/datasetMl';
import { mlTrainingService } from '../../services/mlTrainingService';

interface Props {
  models: TrainedModelArtifact[];
  activeModelId: string;
  onModelSelected: (modelId: string) => void;
}

export const ModelRegistryPanel: React.FC<Props> = ({
  models,
  activeModelId,
  onModelSelected
}) => {
  const [showComparison, setShowComparison] = useState(false);

  const handleSetActive = (modelId: string) => {
    mlTrainingService.setActiveModel(modelId);
    onModelSelected(modelId);
  };

  const rfModel = models.find(m => m.modelType === 'RANDOM_FOREST');
  const ifModel = models.find(m => m.modelType === 'ISOLATION_FOREST');

  return (
    <div id="model-registry-panel" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-indigo-500/10 text-indigo-400">
            <FolderGit2 className="w-5 h-5" />
          </div>
          <div>
            <h3 className="font-semibold text-slate-100 text-sm tracking-wide">
              Model Artifact Registry & Versioning
            </h3>
            <p className="text-xs text-slate-400">
              Persisted models, preprocessing versions, and active model runtime assignment
            </p>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setShowComparison(!showComparison)}
          className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors self-start sm:self-auto"
        >
          {showComparison ? 'Hide Comparison' : 'Compare RF vs Isolation Forest'}
        </button>
      </div>

      {/* Model Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {models.map(model => {
          const isActive = model.modelId === activeModelId;
          const isRf = model.modelType === 'RANDOM_FOREST';

          return (
            <div
              key={model.modelId}
              className={`p-4 rounded-xl border transition-all ${
                isActive
                  ? 'border-indigo-500 bg-indigo-500/10 shadow-sm ring-1 ring-indigo-500/30'
                  : 'border-slate-800 bg-slate-950/60 hover:border-slate-700'
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <div
                    className={`p-1.5 rounded-lg ${
                      isRf
                        ? 'bg-purple-500/20 text-purple-400'
                        : 'bg-cyan-500/20 text-cyan-400'
                    }`}
                  >
                    {isRf ? <TreePine className="w-4 h-4" /> : <Activity className="w-4 h-4" />}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-200 text-xs font-mono">
                        {model.modelId}
                      </span>
                      {isActive && (
                        <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-300 font-semibold flex items-center gap-1">
                          <CheckCircle className="w-3 h-3" /> ACTIVE MODEL
                        </span>
                      )}
                    </div>
                    <span className="text-[11px] text-slate-400 font-mono">
                      {model.modelVersion} • {model.modelType}
                    </span>
                  </div>
                </div>

                <span
                  className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                    model.modelStatus === 'TRAINED'
                      ? 'bg-emerald-500/20 text-emerald-300'
                      : 'bg-blue-500/20 text-blue-300'
                  }`}
                >
                  {model.modelStatus}
                </span>
              </div>

              <div className="mt-3.5 space-y-1.5 text-xs text-slate-300 font-mono border-t border-slate-800/80 pt-2.5">
                <div className="flex justify-between">
                  <span className="text-slate-500">Dataset Source:</span>
                  <span className="text-slate-200 truncate max-w-[180px]">{model.datasetName}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Training Samples:</span>
                  <span className="text-slate-200">{model.trainRows} ({model.featureCount} features)</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Split / Seed:</span>
                  <span className="text-slate-200">
                    {(model.splitRatio * 100).toFixed(0)}% train / seed {model.randomSeed}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-slate-500">Classification Classes:</span>
                  <span className="text-slate-200">{model.classLabels.length} classes</span>
                </div>
              </div>

              {model.notes && (
                <p className="text-[11px] text-slate-400 mt-2.5 bg-slate-900/60 p-2 rounded border border-slate-800/60 leading-relaxed">
                  {model.notes}
                </p>
              )}

              <div className="mt-4 pt-2 flex items-center justify-end">
                {!isActive ? (
                  <button
                    type="button"
                    onClick={() => handleSetActive(model.modelId)}
                    className="px-3 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-medium flex items-center gap-1.5 transition-colors shadow-sm"
                  >
                    <span>Set Active for Threat Detection</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                ) : (
                  <span className="text-xs text-emerald-400 font-medium flex items-center gap-1">
                    <CheckCircle className="w-3.5 h-3.5" /> Currently In Service
                  </span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Model Comparison Table */}
      {showComparison && (
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3 mt-4">
          <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
            <Layers className="w-4 h-4 text-cyan-400" />
            Supervised vs Unsupervised Model Architectural Comparison
          </h4>

          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs border-collapse font-mono">
              <thead className="border-b border-slate-800 text-slate-400 text-[11px]">
                <tr>
                  <th className="py-2 px-3">Dimension</th>
                  <th className="py-2 px-3 text-purple-300">Random Forest Classifier</th>
                  <th className="py-2 px-3 text-cyan-300">Isolation Forest Anomaly Detector</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 text-xs">
                <tr>
                  <td className="py-2 px-3 text-slate-400 font-medium">Learning Paradigm</td>
                  <td className="py-2 px-3 text-slate-200">Supervised Multi-Class Classification</td>
                  <td className="py-2 px-3 text-slate-200">Unsupervised Outlier Isolation</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 text-slate-400 font-medium">Cybersecurity Objective</td>
                  <td className="py-2 px-3 text-slate-200">Specific Threat Typing (DDoS, PortScan, Infiltration, Brute Force)</td>
                  <td className="py-2 px-3 text-slate-200">Zero-Day / Novel Threat Anomaly Flagging</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 text-slate-400 font-medium">Imbalance Handling</td>
                  <td className="py-2 px-3 text-slate-200"><code>class_weight='balanced'</code> penalty scaling</td>
                  <td className="py-2 px-3 text-slate-200">Configurable <code>contamination</code> parameter</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 text-slate-400 font-medium">Decision Boundary</td>
                  <td className="py-2 px-3 text-slate-200">Majority vote across ensemble of decision trees</td>
                  <td className="py-2 px-3 text-slate-200">Short path length in isolation binary tree structures</td>
                </tr>
                <tr>
                  <td className="py-2 px-3 text-slate-400 font-medium">Traceability Output</td>
                  <td className="py-2 px-3 text-slate-200">Multi-class probability distribution</td>
                  <td className="py-2 px-3 text-slate-200">Continuous anomaly score (-0.5 to 0.5 normalized)</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
