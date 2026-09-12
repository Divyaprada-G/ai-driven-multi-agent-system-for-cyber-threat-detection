import React from 'react';
import { Database, Filter, Sliders, Cpu, Brain, CheckCircle2, FileText, ArrowRight, ShieldAlert } from 'lucide-react';

interface ThreatPipelineViewProps {
  currentStage?: string;
}

export const ThreatPipelineView: React.FC<ThreatPipelineViewProps> = () => {
  const PIPELINE_STEPS = [
    {
      id: 'DATA',
      label: '1. Data Ingestion',
      subtext: 'CorrelatedEvent[]',
      icon: Database,
      color: 'text-cyan-400',
      border: 'border-cyan-700/50',
      bg: 'bg-cyan-950/40'
    },
    {
      id: 'PREPROCESSING',
      label: '2. Preprocessing',
      subtext: 'Impute missing / nulls',
      icon: Filter,
      color: 'text-sky-400',
      border: 'border-sky-700/50',
      bg: 'bg-sky-950/40'
    },
    {
      id: 'FEATURE_EXTRACTION',
      label: '3. Feature Extraction',
      subtext: '18 Raw Signals',
      icon: Sliders,
      color: 'text-indigo-400',
      border: 'border-indigo-700/50',
      bg: 'bg-indigo-950/40'
    },
    {
      id: 'NORMALIZATION',
      label: '4. Normalization',
      subtext: 'Min-Max Scaling [0,1]',
      icon: Sliders,
      color: 'text-purple-400',
      border: 'border-purple-700/50',
      bg: 'bg-purple-950/40'
    },
    {
      id: 'MODEL',
      label: '5. Detection Model',
      subtext: 'RF / IF / Demo Engine',
      icon: Cpu,
      color: 'text-amber-400',
      border: 'border-amber-700/50',
      bg: 'bg-amber-950/40'
    },
    {
      id: 'PREDICTION',
      label: '6. Classification',
      subtext: '10 Threat Classes',
      icon: Brain,
      color: 'text-emerald-400',
      border: 'border-emerald-700/50',
      bg: 'bg-emerald-950/40'
    },
    {
      id: 'CONFIDENCE',
      label: '7. Confidence Scoring',
      subtext: 'Calibrated Probability',
      icon: CheckCircle2,
      color: 'text-teal-400',
      border: 'border-teal-700/50',
      bg: 'bg-teal-950/40'
    },
    {
      id: 'EXPLANATION',
      label: '8. Explainable AI',
      subtext: 'Causal Attribution',
      icon: FileText,
      color: 'text-rose-400',
      border: 'border-rose-700/50',
      bg: 'bg-rose-950/40'
    },
    {
      id: 'RESULT',
      label: '9. Threat Result',
      subtext: 'ThreatDetectionResult',
      icon: ShieldAlert,
      color: 'text-cyan-400',
      border: 'border-cyan-500',
      bg: 'bg-cyan-900/50'
    }
  ];

  return (
    <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
        <div>
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-cyan-400 flex items-center gap-1.5">
            <Cpu className="w-3.5 h-3.5" />
            End-to-End Threat Detection Inference Pipeline
          </h3>
          <p className="text-[11px] text-slate-400">
            Systematic progression from correlated security clusters to explainable ML classification.
          </p>
        </div>
        <div className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400 self-start sm:self-auto">
          Phase-I ML Architecture
        </div>
      </div>

      <div className="overflow-x-auto pb-1">
        <div className="flex items-center gap-1.5 min-w-[860px]">
          {PIPELINE_STEPS.map((step, idx) => {
            const Icon = step.icon;
            const isLast = idx === PIPELINE_STEPS.length - 1;
            return (
              <React.Fragment key={step.id}>
                <div
                  className={`flex-1 p-2 rounded-lg border ${step.border} ${step.bg} flex flex-col justify-between min-h-[64px]`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono text-slate-300 font-semibold truncate">
                      {step.label}
                    </span>
                    <Icon className={`w-3.5 h-3.5 ${step.color} shrink-0 ml-1`} />
                  </div>
                  <div className="text-[9px] font-mono text-slate-400 mt-1 truncate">
                    {step.subtext}
                  </div>
                </div>
                {!isLast && (
                  <ArrowRight className="w-3.5 h-3.5 text-slate-600 shrink-0 mx-0.5" />
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    </div>
  );
};
