import React, { useState } from 'react';
import { AlertTriangle, Terminal, CheckCircle2, Info, ChevronDown, ChevronUp, Copy, Check } from 'lucide-react';
import { MLBackendStatus, ModelOperationalStatus } from '../../types/datasetMl';

interface Props {
  backendStatus: MLBackendStatus;
  activeModelStatus: ModelOperationalStatus;
  onRefreshHealth: () => void;
}

export const ModelStatusAlert: React.FC<Props> = ({
  backendStatus,
  activeModelStatus,
  onRefreshHealth
}) => {
  const [showInstructions, setShowInstructions] = useState(false);
  const [copied, setCopied] = useState(false);

  const isConfigured = backendStatus.backendConfigured;

  const handleCopy = () => {
    const text = `cd ml\npip install -r requirements.txt\npython train_model.py ../data/CICIDS2017.csv Label`;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div id="ml-backend-status-banner" className="space-y-3">
      {!isConfigured ? (
        <div className="rounded-xl border border-amber-500/40 bg-amber-500/10 p-4 backdrop-blur-sm">
          <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
            <div className="flex items-start gap-3">
              <div className="p-2 rounded-lg bg-amber-500/20 text-amber-400 mt-0.5">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-semibold text-amber-200 tracking-wide text-sm">
                    REAL ML TRAINING BACKEND NOT CONFIGURED
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300 font-mono">
                    ACADEMIC INTEGRITY ENFORCED
                  </span>
                </div>
                <p className="text-xs text-slate-300 mt-1 max-w-3xl leading-relaxed">
                  Real model training has not yet been executed because scikit-learn is not active in this container.
                  To uphold academic integrity, simulated metrics will <strong className="text-amber-300 font-semibold">NOT</strong> be fabricated.
                  You can inspect schemas, configure leakage-free pipelines, run the Demo Mode reference model, or execute actual training locally.
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2 self-end md:self-center">
              <button
                type="button"
                onClick={() => setShowInstructions(!showInstructions)}
                className="px-3 py-1.5 rounded-lg border border-amber-500/30 bg-amber-500/15 hover:bg-amber-500/25 text-amber-200 text-xs font-medium flex items-center gap-1.5 transition-colors"
              >
                <Terminal className="w-3.5 h-3.5" />
                <span>Local Setup Guide</span>
                {showInstructions ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
              </button>

              <button
                type="button"
                onClick={onRefreshHealth}
                className="px-3 py-1.5 rounded-lg border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
              >
                Check Backend
              </button>
            </div>
          </div>

          {showInstructions && (
            <div className="mt-4 pt-3 border-t border-amber-500/20">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-semibold text-amber-300 flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5" />
                  Terminal Commands for Real Scikit-Learn Training:
                </span>
                <button
                  type="button"
                  onClick={handleCopy}
                  className="text-xs text-slate-400 hover:text-slate-200 flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 transition-colors"
                >
                  {copied ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  <span>{copied ? 'Copied' : 'Copy'}</span>
                </button>
              </div>

              <div className="bg-slate-950 rounded-lg p-3 font-mono text-xs text-slate-300 border border-slate-800 space-y-1">
                <p className="text-slate-500"># 1. Open the ml directory</p>
                <p className="text-emerald-400">cd ml</p>
                <p className="text-slate-500 mt-2"># 2. Install production dependencies</p>
                <p className="text-emerald-400">pip install -r requirements.txt</p>
                <p className="text-slate-500 mt-2"># 3. Train authentic Random Forest model on CICIDS2017</p>
                <p className="text-emerald-400">python train_model.py ../data/CICIDS2017.csv Label</p>
                <p className="text-slate-500 mt-2"># Artifacts are automatically persisted to ml/artifacts/</p>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4">
          <div className="flex items-center gap-3">
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
            <div>
              <span className="font-semibold text-emerald-200 text-sm">REAL ML BACKEND CONNECTED</span>
              <p className="text-xs text-emerald-300/80 mt-0.5">
                Scikit-Learn Python engine is active. Actual model training, validation, and inference are enabled.
              </p>
            </div>
          </div>
        </div>
      )}

      {activeModelStatus === 'DEMO_MODEL' && (
        <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-blue-500/10 border border-blue-500/20 text-xs text-blue-300">
          <Info className="w-4 h-4 text-blue-400 shrink-0" />
          <span>
            <strong>Reference Mode:</strong> Active model is loaded from reference specifications.
            To generate validated academic evaluation metrics, train on an uploaded or benchmark dataset.
          </span>
        </div>
      )}
    </div>
  );
};
