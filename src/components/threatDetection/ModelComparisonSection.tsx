import React from 'react';
import { GitCompare, Cpu, ShieldCheck } from 'lucide-react';
import { ModelStatus } from '../../types/threatDetection';

interface ModelComparisonProps {
  rfStatus: ModelStatus;
  ifStatus: ModelStatus;
}

export const ModelComparisonSection: React.FC<ModelComparisonProps> = ({
  rfStatus,
  ifStatus
}) => {
  const MODELS = [
    {
      name: 'Random Forest Threat Classifier',
      type: 'Ensemble Decision Trees',
      paradigm: 'Supervised Learning',
      target: 'Multi-Class Attack Categorization (10 Classes)',
      status: rfStatus,
      trainingStatus: rfStatus === 'TRAINED' ? 'Trained' : 'Training Required (No weights loaded)',
      evaluationStatus: rfStatus === 'TRAINED' ? 'Evaluated on Holdout' : 'Not evaluated yet',
      featuresRequired: '18 Normalized Features',
      notes: 'Maps correlated event vectors to discrete threat classifications (MITRE tactics).'
    },
    {
      name: 'Isolation Forest Anomaly Detector',
      type: 'Unsupervised Isolation Trees',
      paradigm: 'Unsupervised Learning',
      target: 'Outlier & Zero-Day Deviation Detection',
      status: ifStatus,
      trainingStatus: ifStatus === 'TRAINED' ? 'Fitted' : 'Anomaly Model: NOT TRAINED',
      evaluationStatus: ifStatus === 'TRAINED' ? 'Baseline Validated' : 'Not evaluated yet',
      featuresRequired: '18 Normalized Features',
      notes: 'Calculates path-length dispersion anomaly score s(x, n) ∈ [0.0, 1.0].'
    },
    {
      name: 'Rule-Based Demo Engine',
      type: 'Deterministic Correlation Heuristics',
      paradigm: 'Expert System Rules',
      target: 'Deterministic Explainable Proof-of-Concept',
      status: 'DEMO' as ModelStatus,
      trainingStatus: 'DEMO / RULE-BASED / NOT TRAINED',
      evaluationStatus: 'Deterministic Rules Active',
      featuresRequired: 'Correlated Findings & Entity Pivots',
      notes: 'Provides transparent evidence-based classification while awaiting Python backend.'
    }
  ];

  return (
    <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h4 className="text-sm font-bold text-white font-mono flex items-center gap-1.5">
            <GitCompare className="w-4 h-4 text-cyan-400" />
            Model Architecture Matrix & Comparison
          </h4>
          <p className="text-[11px] text-slate-400">
            Phase-I candidate models for supervised threat categorization vs unsupervised anomaly identification.
          </p>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400">
          Academic Architecture Audit
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono border border-slate-800 rounded-lg overflow-hidden">
          <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
            <tr>
              <th className="p-2.5">Model Name</th>
              <th className="p-2.5">Architecture</th>
              <th className="p-2.5">Paradigm</th>
              <th className="p-2.5">Model Status</th>
              <th className="p-2.5">Training Status</th>
              <th className="p-2.5">Evaluation Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 bg-slate-900/40">
            {MODELS.map((m, idx) => (
              <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                <td className="p-2.5 font-bold text-white flex items-center gap-2">
                  <Cpu className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span>{m.name}</span>
                </td>
                <td className="p-2.5 text-slate-300">{m.type}</td>
                <td className="p-2.5">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    m.paradigm.includes('Supervised')
                      ? 'bg-blue-950 text-blue-300 border border-blue-800'
                      : m.paradigm.includes('Unsupervised')
                      ? 'bg-purple-950 text-purple-300 border border-purple-800'
                      : 'bg-indigo-950 text-indigo-300 border border-indigo-800'
                  }`}>
                    {m.paradigm}
                  </span>
                </td>
                <td className="p-2.5">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    m.status === 'TRAINED' || m.status === 'CONNECTED'
                      ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                      : m.status === 'NOT_TRAINED'
                      ? 'bg-amber-950 text-amber-300 border border-amber-800'
                      : 'bg-cyan-950 text-cyan-300 border border-cyan-800'
                  }`}>
                    {m.status}
                  </span>
                </td>
                <td className="p-2.5 text-slate-300">{m.trainingStatus}</td>
                <td className="p-2.5 text-slate-400">{m.evaluationStatus}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
