/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Deterministic Project Demo Mode & Scenario Controller
 *
 * Implements Sections 33-39 of Prompt 10:
 * - Scenario 1: Multi-Stage Infiltration
 * - Scenario 2: Web Application Exploit Attempt
 * - Scenario 3: System Privilege Escalation
 * - Scenario 4: Benign Operational Baseline
 * - Pipeline progression execution
 * - Non-destructive reset to default state
 * - Clear DEMO DATA indicators
 */

import React, { useState } from 'react';
import {
  Sparkles,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  X,
  Layers,
  ShieldAlert,
  Server,
  Globe,
  Network,
  Info
} from 'lucide-react';
import { demoScenarioService } from '../../services/demoScenarioService';

interface DemoScenarioModalProps {
  isOpen: boolean;
  onClose: () => void;
  onScenarioLoaded: (scenarioId: string) => void;
  onResetComplete: () => void;
}

export const DemoScenarioModal: React.FC<DemoScenarioModalProps> = ({
  isOpen,
  onClose,
  onScenarioLoaded,
  onResetComplete
}) => {
  const [loadingScenario, setLoadingScenario] = useState<string | null>(null);
  const [activeMessage, setActiveMessage] = useState<string | null>(null);

  if (!isOpen) return null;

  const scenarios = demoScenarioService.getScenarios();
  const currentScenarioId = demoScenarioService.getActiveScenarioId();

  const handleRunScenario = async (scenarioId: string) => {
    setLoadingScenario(scenarioId);
    try {
      const res = await demoScenarioService.loadScenario(scenarioId as any);
      setActiveMessage(res.message);
      onScenarioLoaded(scenarioId);
      setTimeout(() => {
        setLoadingScenario(null);
      }, 500);
    } catch (err: any) {
      setActiveMessage(`Error: ${err.message}`);
      setLoadingScenario(null);
    }
  };

  const handleReset = async () => {
    setLoadingScenario('reset');
    try {
      const res = await demoScenarioService.resetToCleanState();
      setActiveMessage(res.message);
      onResetComplete();
      setTimeout(() => {
        setLoadingScenario(null);
      }, 500);
    } catch (err: any) {
      setActiveMessage(`Error: ${err.message}`);
      setLoadingScenario(null);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-3xl w-full p-6 shadow-2xl space-y-4 font-mono text-xs max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div className="flex items-center gap-2.5">
            <div className="p-2 rounded-lg bg-indigo-950 border border-indigo-800 text-indigo-400">
              <Sparkles className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white flex items-center gap-2">
                Project Demonstration & Academic Simulation Scenarios
              </h3>
              <p className="text-[11px] text-slate-400">
                Load deterministic multi-agent attack workflows or reset telemetry state
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Message Banner if any */}
        {activeMessage && (
          <div className="p-3 bg-cyan-950/60 border border-cyan-700 rounded-lg text-cyan-300 flex items-center gap-2 animate-in fade-in duration-150">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{activeMessage}</span>
          </div>
        )}

        {/* Scenarios Grid */}
        <div className="space-y-3">
          <span className="text-[10px] text-slate-500 uppercase font-bold block">
            Select an Evaluation Scenario:
          </span>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {scenarios.map(scenario => {
              const isActive = currentScenarioId === scenario.id;
              const isExecuting = loadingScenario === scenario.id;

              return (
                <div
                  key={scenario.id}
                  className={`p-4 rounded-xl border transition-all flex flex-col justify-between ${
                    isActive
                      ? 'bg-slate-950 border-cyan-500 shadow-md ring-1 ring-cyan-500/30'
                      : 'bg-slate-950/60 border-slate-800 hover:border-slate-700'
                  }`}
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] text-slate-500 font-bold uppercase">
                        {scenario.id.replace('_', ' ')}
                      </span>
                      {isActive && (
                        <span className="px-2 py-0.5 rounded text-[9px] bg-cyan-950 text-cyan-300 border border-cyan-700 font-bold">
                          ACTIVE
                        </span>
                      )}
                    </div>

                    <h4 className="text-sm font-bold text-white">{scenario.name}</h4>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      {scenario.description}
                    </p>

                    <div className="pt-2 border-t border-slate-900 space-y-1 text-[10px]">
                      <div className="text-slate-500">
                        Target Severity: <strong className="text-rose-400">{scenario.severity}</strong>
                      </div>
                      <div className="text-slate-500 truncate">
                        Expected Outcome: <strong className="text-slate-300">{scenario.expectedFlow[scenario.expectedFlow.length - 1] || 'Triage Complete'}</strong>
                      </div>
                    </div>
                  </div>

                  <div className="pt-4 mt-2 border-t border-slate-900 flex items-center justify-between">
                    <span className="text-[10px] text-slate-500">
                      Agents: {scenario.participatingAgents.join(', ')}
                    </span>
                    <button
                      onClick={() => handleRunScenario(scenario.id)}
                      disabled={isExecuting}
                      className={`px-3 py-1.5 rounded text-[11px] font-bold transition-all flex items-center gap-1.5 ${
                        isActive
                          ? 'bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700'
                          : 'bg-indigo-600 hover:bg-indigo-500 text-white shadow'
                      }`}
                    >
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>{isExecuting ? 'Running Pipeline...' : isActive ? 'Re-run Scenario' : 'Execute Scenario'}</span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Reset & Academic Safety Section */}
        <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-[11px] text-slate-400">
            <Info className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>
              All scenarios execute in a safe simulated runtime with full traceability.
            </span>
          </div>

          <button
            onClick={handleReset}
            disabled={loadingScenario === 'reset'}
            className="px-4 py-2 rounded-lg bg-slate-800 hover:bg-rose-950 text-slate-300 hover:text-rose-300 border border-slate-700 hover:border-rose-800 text-xs font-bold transition-colors flex items-center gap-2"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>{loadingScenario === 'reset' ? 'Resetting...' : 'Reset to Clean State'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
