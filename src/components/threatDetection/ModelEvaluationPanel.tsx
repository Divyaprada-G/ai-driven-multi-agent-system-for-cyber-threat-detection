import React, { useState } from 'react';
import { BarChart2, Play, RefreshCw, AlertCircle, CheckCircle2, Shield } from 'lucide-react';
import { ModelEvaluationMetrics } from '../../types/threatDetection';
import { ModelEvaluator } from '../../services/threatDetection/modelEvaluator';

export const ModelEvaluationPanel: React.FC = () => {
  const [metrics, setMetrics] = useState<ModelEvaluationMetrics>(ModelEvaluator.getEvaluationMetrics());
  const [isRunning, setIsRunning] = useState(false);

  const handleRunBenchmark = () => {
    setIsRunning(true);
    setTimeout(() => {
      const calculated = ModelEvaluator.runStandardVerificationBenchmark();
      setMetrics(calculated);
      setIsRunning(false);
    }, 400);
  };

  const handleClear = () => {
    ModelEvaluator.clearEvaluation();
    setMetrics(ModelEvaluator.getEvaluationMetrics());
  };

  return (
    <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
        <div>
          <h4 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            <BarChart2 className="w-4 h-4 text-cyan-400" />
            Model Statistical Evaluation & Verification Benchmark
          </h4>
          <p className="text-[11px] text-slate-400">
            Performance metrics calculated exclusively on labeled ground-truth evaluation sets.
          </p>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <button
            id="btn-run-eval-benchmark"
            onClick={handleRunBenchmark}
            disabled={isRunning}
            className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-bold flex items-center gap-1.5 transition-colors shadow-lg shadow-cyan-600/20"
          >
            {isRunning ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Evaluating...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Run Verification Benchmark (20 Samples)</span>
              </>
            )}
          </button>
          {metrics.evaluated && (
            <button
              onClick={handleClear}
              className="px-2.5 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg text-xs font-mono transition-colors"
            >
              Reset
            </button>
          )}
        </div>
      </div>

      {!metrics.evaluated ? (
        <div className="p-6 text-center rounded-lg bg-slate-950/60 border border-slate-800/60 space-y-2">
          <AlertCircle className="w-6 h-6 text-slate-500 mx-auto" />
          <div className="text-xs font-mono font-bold text-slate-300">
            Model Evaluation Status: Not evaluated yet
          </div>
          <p className="text-[11px] text-slate-500 max-w-md mx-auto">
            In accordance with academic integrity mandates, Accuracy, Precision, Recall, and F1 Score are not fabricated or hardcoded. Click "Run Verification Benchmark" to evaluate against a 20-sample labeled ground-truth set.
          </p>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Metadata Banner */}
          <div className="flex items-center justify-between text-xs font-mono bg-slate-950/80 p-2.5 rounded-lg border border-slate-800">
            <span className="text-cyan-300">
              Dataset: <strong>{metrics.datasetName}</strong> ({metrics.sampleCount} Samples)
            </span>
            <span className="text-slate-400">
              Evaluated: {new Date(metrics.evaluationDate || '').toLocaleTimeString()}
            </span>
          </div>

          {/* 4 Score Cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 font-mono">
            <div className="p-3 bg-slate-950 rounded-lg border border-cyan-800/60">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
                Calculated Accuracy
              </span>
              <span className="text-xl font-bold text-cyan-400">
                {(metrics.accuracy! * 100).toFixed(1)}%
              </span>
              <span className="text-[9px] text-slate-500 block mt-0.5">(TP + TN) / Total</span>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-indigo-800/60">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
                Precision
              </span>
              <span className="text-xl font-bold text-indigo-400">
                {(metrics.precision! * 100).toFixed(1)}%
              </span>
              <span className="text-[9px] text-slate-500 block mt-0.5">TP / (TP + FP)</span>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-purple-800/60">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
                Recall (Sensitivity)
              </span>
              <span className="text-xl font-bold text-purple-400">
                {(metrics.recall! * 100).toFixed(1)}%
              </span>
              <span className="text-[9px] text-slate-500 block mt-0.5">TP / (TP + FN)</span>
            </div>

            <div className="p-3 bg-slate-950 rounded-lg border border-emerald-800/60">
              <span className="text-[10px] text-slate-400 uppercase tracking-wider block">
                F1 Score (Harmonic Mean)
              </span>
              <span className="text-xl font-bold text-emerald-400">
                {(metrics.f1Score! * 100).toFixed(1)}%
              </span>
              <span className="text-[9px] text-slate-500 block mt-0.5">2 × (P × R) / (P + R)</span>
            </div>
          </div>

          {/* Confusion Matrix */}
          {metrics.confusionMatrix && (
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              <div className="flex items-center justify-between text-xs font-mono">
                <span className="text-slate-300 font-bold">Empirical Confusion Matrix (Binary Threat / Non-Threat):</span>
                <span className="text-slate-500 text-[10px]">Ground Truth vs Model Output</span>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-center text-xs font-mono">
                <div className="p-2 rounded bg-emerald-950/40 border border-emerald-800/60">
                  <div className="text-[10px] text-slate-400">True Positive (TP)</div>
                  <div className="text-base font-bold text-emerald-300">{metrics.confusionMatrix.tp}</div>
                  <div className="text-[9px] text-emerald-500">Correctly identified threats</div>
                </div>

                <div className="p-2 rounded bg-rose-950/40 border border-rose-800/60">
                  <div className="text-[10px] text-slate-400">False Positive (FP)</div>
                  <div className="text-base font-bold text-rose-300">{metrics.confusionMatrix.fp}</div>
                  <div className="text-[9px] text-rose-500">Benign misclassified as threat</div>
                </div>

                <div className="p-2 rounded bg-slate-900 border border-slate-700">
                  <div className="text-[10px] text-slate-400">True Negative (TN)</div>
                  <div className="text-base font-bold text-slate-200">{metrics.confusionMatrix.tn}</div>
                  <div className="text-[9px] text-slate-400">Correctly identified benign</div>
                </div>

                <div className="p-2 rounded bg-amber-950/40 border border-amber-800/60">
                  <div className="text-[10px] text-slate-400">False Negative (FN)</div>
                  <div className="text-base font-bold text-amber-300">{metrics.confusionMatrix.fn}</div>
                  <div className="text-[9px] text-amber-500">Threat missed by model</div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
