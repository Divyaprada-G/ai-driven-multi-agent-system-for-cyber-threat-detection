import React, { useState, useEffect } from 'react';
import { ShieldAlert, Cpu, Activity, AlertTriangle, CheckCircle2, Search, Sliders, Play } from 'lucide-react';
import { ThreatDetectionResult } from '../types';
import { threatDetectionService, ThreatModelConfig } from '../services/threatDetectionService';
import { StatCard } from '../components/common/StatCard';
import { StatusBadge } from '../components/common/StatusBadge';

export const ThreatDetectionPage: React.FC = () => {
  const [modelInfo, setModelInfo] = useState<ThreatModelConfig | null>(null);
  const [detections, setDetections] = useState<ThreatDetectionResult[]>([]);
  const [testPayload, setTestPayload] = useState('');
  const [isSimulating, setIsSimulating] = useState(false);

  useEffect(() => {
    async function load() {
      const [model, dets] = await Promise.all([
        threatDetectionService.getActiveModelInfo(),
        threatDetectionService.getDetectionResults()
      ]);
      setModelInfo(model);
      setDetections(dets);
    }
    load();
  }, []);

  const handleSimulateAnomaly = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!testPayload.trim()) return;
    setIsSimulating(true);
    try {
      const result = await threatDetectionService.analyzeAnomaly(testPayload);
      setDetections(prev => [result, ...prev]);
      setTestPayload('');
    } finally {
      setIsSimulating(false);
    }
  };

  if (!modelInfo) {
    return <div className="p-8 text-center text-slate-500 font-mono">Loading ML Engine telemetry...</div>;
  }

  return (
    <div className="space-y-6" id="page-threat-detection">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest">
            Machine Learning Inference Pipeline
          </span>
        </div>
        <h2 className="text-xl font-bold text-white tracking-tight">
          AI/ML Threat Detection Engine
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          Supervised and unsupervised detection architecture utilizing Isolation Forests for anomalous flow identification, XGBoost for packet scoring, and Attention Sequence models for lateral movement classification.
        </p>
      </div>

      {/* 11. MODEL STATUS & METRICS */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
        <div className="p-4 bg-slate-900/80 border border-cyan-500/40 rounded-xl space-y-1 sm:col-span-2">
          <div className="text-xs text-slate-400 font-mono">Detection Model</div>
          <div className="text-base font-bold text-white tracking-tight">{modelInfo.modelName}</div>
          <div className="text-[11px] text-cyan-400 font-mono flex items-center gap-2">
            <span>Version: {modelInfo.version}</span>
            <span>•</span>
            <span className="text-emerald-400 font-bold">{modelInfo.status}</span>
          </div>
        </div>

        <StatCard
          id="stat-ml-events-analyzed"
          title="Events Analyzed"
          value={modelInfo.eventsAnalyzedCount}
          subtitle="Sliding 24h window"
          icon={Activity}
          variant="info"
        />

        <StatCard
          id="stat-ml-threats-detected"
          title="Threats Detected"
          value={modelInfo.threatsDetectedCount}
          subtitle="Model positive triggers"
          icon={AlertTriangle}
          variant="critical"
        />

        <StatCard
          id="stat-ml-confidence"
          title="Detection Confidence"
          value={`${modelInfo.accuracy}%`}
          subtitle={`F1 Score: ${modelInfo.f1Score}%`}
          icon={ShieldAlert}
          variant="emerald"
        />
      </div>

      {/* Anomaly Detection Testing Sandbox */}
      <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <Sliders className="w-4 h-4 text-cyan-400" />
              Threat Anomaly Simulation & Evaluation Sandbox
            </h3>
            <p className="text-xs text-slate-400">
              Input synthetic log text or byte sequence to test future Python/ML inference endpoint.
            </p>
          </div>
          <span className="text-xs font-mono text-slate-500">
            Target Endpoint: POST /api/v1/ml/infer
          </span>
        </div>

        <form onSubmit={handleSimulateAnomaly} className="space-y-3">
          <textarea
            id="textarea-test-payload"
            rows={3}
            placeholder="Paste raw log entry or attack vector (e.g. 192.168.1.105 - - [11/Sep/2026] 'GET /admin?cmd=whoami HTTP/1.1' 200 420)..."
            value={testPayload}
            onChange={e => setTestPayload(e.target.value)}
            className="w-full p-3 text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 resize-none"
          />

          <div className="flex items-center justify-between">
            <div className="text-[11px] font-mono text-slate-500">
              Inference pipeline ready for Scikit-Learn / PyTorch model serving integration.
            </div>
            <button
              id="btn-run-inference-eval"
              type="submit"
              disabled={isSimulating || !testPayload.trim()}
              className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white rounded-lg text-xs font-mono font-bold inline-flex items-center gap-2 transition-colors"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{isSimulating ? 'Evaluating...' : 'Simulate Model Inference'}</span>
            </button>
          </div>
        </form>
      </div>

      {/* Detection Results */}
      <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-xl space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              ML Detection Results & Anomaly Scores
            </h3>
            <p className="text-xs text-slate-400">
              Evaluated against baseline behavioral distributions.
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {detections.map(det => (
            <div
              key={det.id}
              id={`card-det-${det.id.toLowerCase()}`}
              className="p-4 bg-slate-950/80 border border-slate-800 rounded-xl space-y-3 flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between text-xs font-mono mb-2">
                  <span className="text-cyan-400">{det.id}</span>
                  <span className="text-slate-500">{det.timestamp.slice(11)}</span>
                </div>

                <h4 className="text-sm font-bold text-white font-sans">{det.threatType}</h4>
                <div className="text-[11px] text-slate-400 font-mono mt-0.5">
                  Category: <span className="text-slate-200">{det.category}</span>
                </div>

                {/* Scores */}
                <div className="mt-3 p-2.5 bg-slate-900/70 rounded-lg border border-slate-800/80 grid grid-cols-2 gap-2 text-xs font-mono">
                  <div>
                    <span className="text-slate-500 text-[10px] block">Anomaly Score</span>
                    <span className="text-rose-400 font-bold">{det.anomalyScore}</span>
                  </div>
                  <div>
                    <span className="text-slate-500 text-[10px] block">Deviation</span>
                    <span className="text-amber-400 font-bold">+{det.baselineDeviation}σ</span>
                  </div>
                </div>

                {/* Evidence list */}
                <div className="mt-3 space-y-1">
                  <span className="text-[10px] uppercase font-mono text-slate-500 tracking-wider">
                    Model Extracted Evidence:
                  </span>
                  <ul className="space-y-1">
                    {det.evidence.map((ev, idx) => (
                      <li key={idx} className="text-[11px] text-slate-300 font-mono">
                        • {ev}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>

              <div className="pt-2 border-t border-slate-800/80 text-[10px] font-mono text-slate-500 flex justify-between items-center">
                <span>Model: {det.model.slice(0, 24)}...</span>
                <span className="text-cyan-400 font-bold">{(det.confidence * 100).toFixed(0)}% Conf</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
