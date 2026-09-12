import React from 'react';
import {
  Award,
  BarChart3,
  CheckCircle2,
  AlertTriangle,
  Info,
  Grid,
  FileCheck2,
  TrendingUp,
  HelpCircle
} from 'lucide-react';
import { TrainedModelArtifact } from '../../types/datasetMl';

interface Props {
  activeModel: TrainedModelArtifact | null;
}

export const EvaluationResultsPanel: React.FC<Props> = ({ activeModel }) => {
  if (!activeModel) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-center text-slate-400 text-xs">
        No active model selected in registry.
      </div>
    );
  }

  const metrics = activeModel.evaluationMetrics;

  return (
    <div id="evaluation-results-panel" className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400">
            <Award className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="font-semibold text-slate-100 text-sm tracking-wide">
                Model Evaluation & Validation Report
              </h3>
              <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-cyan-300 font-mono">
                {activeModel.modelId} ({activeModel.modelType})
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Rigorous test-set metrics calculated strictly on held-out data without leakage
            </p>
          </div>
        </div>

        <div className="text-xs text-slate-400 font-mono self-start sm:self-auto">
          Status: <strong className="text-slate-200">{activeModel.modelStatus}</strong>
        </div>
      </div>

      {/* Honest Empty State when real metrics have not yet been evaluated */}
      {!metrics ? (
        <div className="rounded-xl border border-dashed border-slate-700 p-8 text-center bg-slate-950/40 space-y-3">
          <div className="inline-flex p-3 rounded-full bg-slate-800 text-slate-400">
            <Info className="w-6 h-6 text-amber-400" />
          </div>
          <div className="max-w-md mx-auto space-y-1">
            <h4 className="font-semibold text-slate-200 text-sm">
              NO REAL EVALUATION METRICS AVAILABLE
            </h4>
            <p className="text-xs text-slate-400 leading-relaxed">
              Real model training has not yet been executed for this model artifact.
              In accordance with academic integrity guidelines, performance metrics (Accuracy, F1-Score, Confusion Matrix)
              are <strong className="text-amber-300 font-semibold">never fabricated</strong>.
            </p>
          </div>

          <div className="pt-2 text-[11px] text-slate-500 max-w-lg mx-auto bg-slate-900/60 p-3 rounded-lg border border-slate-800 text-left font-mono">
            <span className="text-slate-400 font-bold block mb-1">To generate validated metrics:</span>
            <span>1. Configure local Python ML worker: <code className="text-cyan-300">pip install -r ml/requirements.txt</code></span><br />
            <span>2. Run evaluation script: <code className="text-cyan-300">python ml/train_model.py data/CICIDS2017.csv Label</code></span>
          </div>
        </div>
      ) : (
        <div className="space-y-6">
          {/* Top Metric Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-6 gap-3">
            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[11px] text-slate-400 block font-medium">Test Accuracy</span>
              <span className="text-xl font-bold text-emerald-400 font-mono">
                {(metrics.accuracy * 100).toFixed(2)}%
              </span>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[11px] text-slate-400 block font-medium">Macro F1</span>
              <span className="text-xl font-bold text-cyan-400 font-mono">
                {(metrics.macroF1 * 100).toFixed(2)}%
              </span>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[11px] text-slate-400 block font-medium">Weighted F1</span>
              <span className="text-xl font-bold text-purple-400 font-mono">
                {(metrics.weightedF1 * 100).toFixed(2)}%
              </span>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[11px] text-slate-400 block font-medium">Macro Precision</span>
              <span className="text-xl font-bold text-blue-400 font-mono">
                {(metrics.macroPrecision * 100).toFixed(2)}%
              </span>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[11px] text-slate-400 block font-medium">Macro Recall</span>
              <span className="text-xl font-bold text-indigo-400 font-mono">
                {(metrics.macroRecall * 100).toFixed(2)}%
              </span>
            </div>

            <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-800">
              <span className="text-[11px] text-slate-400 block font-medium">Held-Out Test Rows</span>
              <span className="text-xl font-bold text-slate-200 font-mono">
                {metrics.evaluatedOnTestRows}
              </span>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Confusion Matrix Table */}
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                  <Grid className="w-3.5 h-3.5 text-cyan-400" />
                  Confusion Matrix (Held-Out Test Set)
                </h4>
                <span className="text-[10px] text-slate-500 font-mono">Rows: True, Cols: Pred</span>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-center text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-slate-800 text-slate-400 font-mono text-[11px]">
                      <th className="py-2 px-2 text-left">True \ Pred</th>
                      {metrics.confusionMatrix.labels.map(lbl => (
                        <th key={lbl} className="py-2 px-2 truncate max-w-[80px]" title={lbl}>
                          {lbl}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 font-mono text-xs">
                    {metrics.confusionMatrix.matrix.map((row, rIdx) => {
                      const trueLabel = metrics.confusionMatrix.labels[rIdx];
                      return (
                        <tr key={rIdx}>
                          <td className="py-2 px-2 text-left font-semibold text-slate-300 truncate max-w-[100px]" title={trueLabel}>
                            {trueLabel}
                          </td>
                          {row.map((val, cIdx) => {
                            const isDiagonal = rIdx === cIdx;
                            return (
                              <td
                                key={cIdx}
                                className={`py-2 px-2 font-bold ${
                                  isDiagonal
                                    ? val > 0
                                      ? 'bg-emerald-500/20 text-emerald-300'
                                      : 'text-slate-500'
                                    : val > 0
                                    ? 'bg-red-500/20 text-red-300'
                                    : 'text-slate-600'
                                }`}
                              >
                                {val}
                              </td>
                            );
                          })}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Per-Class Classification Report */}
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
              <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                <FileCheck2 className="w-3.5 h-3.5 text-purple-400" />
                Per-Class Classification Report
              </h4>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse font-mono">
                  <thead className="border-b border-slate-800 text-slate-400 text-[11px]">
                    <tr>
                      <th className="py-2 px-2">Class</th>
                      <th className="py-2 px-2 text-right">Precision</th>
                      <th className="py-2 px-2 text-right">Recall</th>
                      <th className="py-2 px-2 text-right">F1-Score</th>
                      <th className="py-2 px-2 text-right">Support</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60 text-xs">
                    {metrics.classificationReport.map(item => (
                      <tr key={item.className} className="hover:bg-slate-800/30">
                        <td className="py-2 px-2 text-slate-200 font-medium truncate max-w-[120px]">
                          {item.className}
                        </td>
                        <td className="py-2 px-2 text-right text-cyan-300">
                          {(item.precision * 100).toFixed(1)}%
                        </td>
                        <td className="py-2 px-2 text-right text-indigo-300">
                          {(item.recall * 100).toFixed(1)}%
                        </td>
                        <td className="py-2 px-2 text-right font-bold text-emerald-400">
                          {(item.f1Score * 100).toFixed(1)}%
                        </td>
                        <td className="py-2 px-2 text-right text-slate-400">{item.support}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>

          {/* Feature Importance Bar Chart */}
          {metrics.featureImportances && metrics.featureImportances.length > 0 && (
            <div className="p-4 rounded-lg bg-slate-950 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-semibold text-slate-200 flex items-center gap-1.5">
                  <TrendingUp className="w-3.5 h-3.5 text-blue-400" />
                  Top Feature Importances (Gini Impurity Reduction)
                </h4>
                <span className="text-[10px] text-slate-500">Learned from Random Forest trees</span>
              </div>

              <div className="space-y-2 pt-1">
                {metrics.featureImportances.slice(0, 8).map(fi => {
                  const pct = Math.min(100, Math.max(2, fi.importance * 100 * 2.5));
                  return (
                    <div key={fi.feature} className="space-y-1">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-mono text-slate-300 text-[11px] truncate max-w-sm">
                          #{fi.rank} {fi.feature}
                        </span>
                        <span className="font-mono text-cyan-300 text-[11px]">
                          {(fi.importance * 100).toFixed(2)}%
                        </span>
                      </div>
                      <div className="w-full bg-slate-800 rounded-full h-1.5 overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-blue-500 to-cyan-400 rounded-full"
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
