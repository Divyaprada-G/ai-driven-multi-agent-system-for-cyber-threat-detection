/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Configurable Academic/Demo Risk Model Weights Sandbox
 */

import React, { useState } from 'react';
import { SlidersHorizontal, RotateCcw, Check, Info } from 'lucide-react';
import { RiskModelConfig } from '../../types/riskScoring';
import { RISK_CONFIG } from '../../services/riskScoring/riskConfig';

interface RiskConfigSandboxProps {
  currentConfig: RiskModelConfig;
  onApplyConfig: (newConfig: RiskModelConfig) => void;
}

export const RiskConfigSandbox: React.FC<RiskConfigSandboxProps> = ({
  currentConfig,
  onApplyConfig
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const [weights, setWeights] = useState({
    threatSeverity: Math.round(currentConfig.weights.threatSeverity * 100),
    mlConfidence: Math.round(currentConfig.weights.mlConfidence * 100),
    correlationStrength: Math.round(currentConfig.weights.correlationStrength * 100),
    attackComplexity: Math.round(currentConfig.weights.attackComplexity * 100),
    agentInvolvement: Math.round(currentConfig.weights.agentInvolvement * 100),
    evidenceVolume: Math.round(currentConfig.weights.evidenceVolume * 100),
    affectedEntities: Math.round(currentConfig.weights.affectedEntities * 100)
  });

  const weightValues: number[] = [
    weights.threatSeverity,
    weights.mlConfidence,
    weights.correlationStrength,
    weights.attackComplexity,
    weights.agentInvolvement,
    weights.evidenceVolume,
    weights.affectedEntities
  ];
  const totalWeight: number = weightValues.reduce((a, b) => a + b, 0);

  const handleApply = () => {
    // Normalize to 1.0 sum
    const factor = totalWeight > 0 ? 1 / totalWeight : 1;
    const newWeights = {
      threatSeverity: (weights.threatSeverity * factor),
      mlConfidence: (weights.mlConfidence * factor),
      correlationStrength: (weights.correlationStrength * factor),
      attackComplexity: (weights.attackComplexity * factor),
      agentInvolvement: (weights.agentInvolvement * factor),
      evidenceVolume: (weights.evidenceVolume * factor),
      affectedEntities: (weights.affectedEntities * factor)
    };

    onApplyConfig({
      ...currentConfig,
      weights: newWeights
    });
  };

  const handleReset = () => {
    setWeights({
      threatSeverity: Math.round(RISK_CONFIG.weights.threatSeverity * 100),
      mlConfidence: Math.round(RISK_CONFIG.weights.mlConfidence * 100),
      correlationStrength: Math.round(RISK_CONFIG.weights.correlationStrength * 100),
      attackComplexity: Math.round(RISK_CONFIG.weights.attackComplexity * 100),
      agentInvolvement: Math.round(RISK_CONFIG.weights.agentInvolvement * 100),
      evidenceVolume: Math.round(RISK_CONFIG.weights.evidenceVolume * 100),
      affectedEntities: Math.round(RISK_CONFIG.weights.affectedEntities * 100)
    });
    onApplyConfig(RISK_CONFIG);
  };

  return (
    <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3 font-mono text-xs">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <SlidersHorizontal className="w-4 h-4 text-cyan-400" />
          <span className="font-bold text-white">Configurable Academic/Demo Risk Weights</span>
          <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
            {totalWeight}% Total
          </span>
        </div>

        <div className="flex items-center gap-2 self-end sm:self-auto">
          <button
            onClick={() => setIsOpen(!isOpen)}
            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors"
          >
            {isOpen ? 'Collapse Weights' : 'Adjust Model Weights'}
          </button>
          {isOpen && (
            <>
              <button
                onClick={handleReset}
                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-colors flex items-center gap-1"
              >
                <RotateCcw className="w-3 h-3" />
                <span>Reset</span>
              </button>
              <button
                onClick={handleApply}
                className="px-3 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold transition-colors flex items-center gap-1"
              >
                <Check className="w-3 h-3" />
                <span>Recalculate</span>
              </button>
            </>
          )}
        </div>
      </div>

      {isOpen && (
        <div className="space-y-3 pt-2">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {/* Threat Severity (30%) */}
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Threat Severity</span>
                <span className="text-cyan-400 font-bold">{weights.threatSeverity}%</span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                value={weights.threatSeverity}
                onChange={e => setWeights({ ...weights, threatSeverity: Number(e.target.value) })}
                className="w-full accent-cyan-400"
              />
            </div>

            {/* ML Confidence (20%) */}
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <div className="flex justify-between text-slate-300 mb-1">
                <span>ML Confidence</span>
                <span className="text-cyan-400 font-bold">{weights.mlConfidence}%</span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                value={weights.mlConfidence}
                onChange={e => setWeights({ ...weights, mlConfidence: Number(e.target.value) })}
                className="w-full accent-cyan-400"
              />
            </div>

            {/* Correlation Strength (15%) */}
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Correlation Strength</span>
                <span className="text-cyan-400 font-bold">{weights.correlationStrength}%</span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                value={weights.correlationStrength}
                onChange={e => setWeights({ ...weights, correlationStrength: Number(e.target.value) })}
                className="w-full accent-cyan-400"
              />
            </div>

            {/* Attack Complexity (15%) */}
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Attack Complexity</span>
                <span className="text-cyan-400 font-bold">{weights.attackComplexity}%</span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                value={weights.attackComplexity}
                onChange={e => setWeights({ ...weights, attackComplexity: Number(e.target.value) })}
                className="w-full accent-cyan-400"
              />
            </div>

            {/* Agent Involvement (10%) */}
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Agent Involvement</span>
                <span className="text-cyan-400 font-bold">{weights.agentInvolvement}%</span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                value={weights.agentInvolvement}
                onChange={e => setWeights({ ...weights, agentInvolvement: Number(e.target.value) })}
                className="w-full accent-cyan-400"
              />
            </div>

            {/* Evidence Volume (5%) */}
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Evidence Volume</span>
                <span className="text-cyan-400 font-bold">{weights.evidenceVolume}%</span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                value={weights.evidenceVolume}
                onChange={e => setWeights({ ...weights, evidenceVolume: Number(e.target.value) })}
                className="w-full accent-cyan-400"
              />
            </div>

            {/* Affected Entities (5%) */}
            <div className="p-2.5 rounded bg-slate-950/60 border border-slate-800">
              <div className="flex justify-between text-slate-300 mb-1">
                <span>Affected Entities</span>
                <span className="text-cyan-400 font-bold">{weights.affectedEntities}%</span>
              </div>
              <input
                type="range"
                min="0"
                max="100"
                value={weights.affectedEntities}
                onChange={e => setWeights({ ...weights, affectedEntities: Number(e.target.value) })}
                className="w-full accent-cyan-400"
              />
            </div>
          </div>

          <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[11px] text-slate-400 flex items-center gap-2">
            <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span>
              Weights automatically normalize upon recalculation. Higher severity and confidence weights emphasize high-impact alerts, while higher correlation and complexity weights prioritize multi-stage kill chains.
            </span>
          </div>
        </div>
      )}
    </div>
  );
};
