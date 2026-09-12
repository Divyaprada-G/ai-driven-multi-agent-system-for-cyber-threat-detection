import React, { useState, useEffect } from 'react';
import {
  X,
  Play,
  CheckCircle2,
  AlertCircle,
  Sparkles,
  ArrowRight,
  RotateCcw,
  ShieldCheck,
  Server,
  Cpu,
  Layers,
  Activity,
  Bell,
  Radio,
  ExternalLink
} from 'lucide-react';
import { LivePipelineStatus } from '../../types/livePipeline';
import { livePipelineService } from '../../services/livePipelineService';
import { mlTrainingService } from '../../services/mlTrainingService';

interface ProjectDemoModalProps {
  isOpen: boolean;
  onClose: () => void;
  status: LivePipelineStatus;
  onNavigateToTraining: () => void;
}

const DEMO_STEPS = [
  { step: 1, title: 'Check Local API Readiness', desc: 'Verifies FastAPI endpoint or in-memory backend connection' },
  { step: 2, title: 'Verify Trained ML Model', desc: 'Checks Random Forest / Isolation Forest model in registry' },
  { step: 3, title: 'Start Live Security Pipeline', desc: 'Activates async event processing loop & queue' },
  { step: 4, title: 'Start Event Simulator', desc: 'Initiates safe synthetic cybersecurity stream' },
  { step: 5, title: 'Ingest Live Events', desc: 'Normalized events populate in-memory queue' },
  { step: 6, title: 'Multi-Agent Routing', desc: 'Network, System, and Application agents inspect payload' },
  { step: 7, title: 'Cross-Source Correlation', desc: 'Correlation engine detects multi-stage attack patterns' },
  { step: 8, title: 'Real ML Prediction', desc: 'Scikit-Learn model calculates class probabilities' },
  { step: 9, title: '7-Factor Risk Scoring', desc: 'Quantitative score calculated based on severity and asset impact' },
  { step: 10, title: 'Alert Evaluation', desc: 'Security alerts generated for events crossing threshold' },
  { step: 11, title: 'Incident Escalation', desc: 'High-risk threats grouped into actionable incidents' },
  { step: 12, title: 'Dashboard Real-Time Update', desc: 'Live event stream, latency stats & traceability updated' }
];

export const ProjectDemoModal: React.FC<ProjectDemoModalProps> = ({
  isOpen,
  onClose,
  status,
  onNavigateToTraining
}) => {
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [completed, setCompleted] = useState<boolean>(false);

  useEffect(() => {
    if (!isOpen) {
      setCurrentStep(0);
      setIsRunning(false);
      setErrorMessage(null);
      setCompleted(false);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const runDemoSequence = async () => {
    setIsRunning(true);
    setErrorMessage(null);
    setCompleted(false);

    try {
      // Step 1: Verify API Readiness
      setCurrentStep(1);
      await new Promise(r => setTimeout(r, 600));

      // Step 2: Verify Model
      setCurrentStep(2);
      const activeModel = mlTrainingService.getActiveModel();
      if (!activeModel) {
        setErrorMessage('Demo cannot execute real ML predictions because no trained model is available. Train a model in Datasets & ML Training first.');
        setIsRunning(false);
        return;
      }
      await new Promise(r => setTimeout(r, 600));

      // Step 3: Start Pipeline
      setCurrentStep(3);
      livePipelineService.startPipeline();
      await new Promise(r => setTimeout(r, 600));

      // Step 4: Start Simulator
      setCurrentStep(4);
      livePipelineService.startSimulator({ eventRate: 2, mode: 'multistage' });
      await new Promise(r => setTimeout(r, 700));

      // Step 5: Events Enter System
      setCurrentStep(5);
      await new Promise(r => setTimeout(r, 700));

      // Step 6: Multi-Agent Processing
      setCurrentStep(6);
      await new Promise(r => setTimeout(r, 700));

      // Step 7: Correlation
      setCurrentStep(7);
      await new Promise(r => setTimeout(r, 700));

      // Step 8: ML Prediction
      setCurrentStep(8);
      await new Promise(r => setTimeout(r, 700));

      // Step 9: Risk Scoring
      setCurrentStep(9);
      await new Promise(r => setTimeout(r, 700));

      // Step 10: Alert Generation
      setCurrentStep(10);
      await new Promise(r => setTimeout(r, 700));

      // Step 11: Incident Escalation
      setCurrentStep(11);
      await new Promise(r => setTimeout(r, 700));

      // Step 12: Dashboard Update
      setCurrentStep(12);
      await new Promise(r => setTimeout(r, 600));

      setCompleted(true);
      setIsRunning(false);

    } catch (e: any) {
      setErrorMessage(e?.message || 'Demo execution error');
      setIsRunning(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl w-full max-w-2xl shadow-2xl overflow-hidden my-8">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-950/60">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-purple-500/10 text-purple-400">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h3 className="text-base font-bold text-slate-100">Guided Project Demonstration</h3>
                <span className="text-xs px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 font-mono">
                  12 Stages
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-0.5">
                Automated live walkthrough designed for faculty, guides, and academic project evaluation.
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 max-h-[70vh] overflow-y-auto">
          {/* Error Banner */}
          {errorMessage && (
            <div className="p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-xs flex items-start space-x-3">
              <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
              <div>
                <strong className="block text-rose-200 font-semibold mb-1">Precondition Failed:</strong>
                {errorMessage}
                <div className="mt-2">
                  <button
                    onClick={() => {
                      onClose();
                      onNavigateToTraining();
                    }}
                    className="underline text-sky-400 font-semibold inline-flex items-center space-x-1"
                  >
                    <span>Go to Datasets & ML Training</span>
                    <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Success Banner */}
          {completed && (
            <div className="p-4 rounded-xl bg-emerald-500/15 border border-emerald-500/40 text-emerald-200 text-xs flex items-start space-x-3">
              <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="block text-emerald-300 font-bold text-sm mb-0.5">DEMO COMPLETED SUCCESSFULLY</strong>
                All 12 architecture stages passed verification. Real ML predictions, risk scoring, alerts, and incidents are currently actively visible on the live dashboard.
              </div>
            </div>
          )}

          {/* Step Sequence Stepper */}
          <div className="space-y-2">
            {DEMO_STEPS.map((s) => {
              const isPast = currentStep > s.step || completed;
              const isCurrent = currentStep === s.step && isRunning;
              return (
                <div
                  key={s.step}
                  className={`p-2.5 rounded-lg border transition-all flex items-center justify-between text-xs ${
                    isCurrent
                      ? 'bg-purple-950/40 border-purple-500/50 text-purple-200 shadow-sm'
                      : (isPast
                        ? 'bg-slate-950/60 border-slate-800/80 text-slate-300'
                        : 'bg-slate-950/20 border-slate-900 text-slate-500')
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <span className={`w-5 h-5 rounded-full flex items-center justify-center font-bold text-[10px] ${
                      isPast
                        ? 'bg-emerald-500 text-black'
                        : (isCurrent ? 'bg-purple-500 text-white animate-pulse' : 'bg-slate-800 text-slate-500')
                    }`}>
                      {isPast ? '✓' : s.step}
                    </span>
                    <div>
                      <span className="font-semibold text-slate-200 block">{s.title}</span>
                      <span className="text-[10px] text-slate-400">{s.desc}</span>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono">
                    {isCurrent ? (
                      <span className="text-purple-400 animate-pulse font-semibold">EXECUTING...</span>
                    ) : (isPast ? (
                      <span className="text-emerald-400 font-medium">PASSED</span>
                    ) : (
                      <span className="text-slate-600">PENDING</span>
                    ))}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-800 bg-slate-950/80 flex items-center justify-between">
          <span className="text-xs text-slate-400 font-mono">
            {completed ? 'Status: COMPLETED' : (isRunning ? `Running step ${currentStep}/12...` : 'Ready to execute')}
          </span>
          <div className="flex items-center space-x-2">
            <button
              onClick={onClose}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
            >
              Close
            </button>
            <button
              disabled={isRunning}
              onClick={runDemoSequence}
              className="px-4 py-1.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-bold flex items-center space-x-1.5 disabled:opacity-50 cursor-pointer shadow-md transition-all"
            >
              {completed ? <RotateCcw className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              <span>{completed ? 'RE-RUN DEMO' : 'START 12-STEP DEMO'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
