/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Risk Analysis & Threat Prioritization Page
 */

import React, { useState, useEffect } from 'react';
import {
  Activity,
  ShieldCheck,
  Flame,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  SlidersHorizontal,
  Layers,
  FileCode,
  Info
} from 'lucide-react';
import { RiskAssessment, SeverityLevel, RiskStatus, RiskModelConfig } from '../types';
import { riskService } from '../services/riskService';
import { RiskOverviewCards } from '../components/riskScoring/RiskOverviewCards';
import { RiskDistributionChart } from '../components/riskScoring/RiskDistributionChart';
import { RiskTrendChart } from '../components/riskScoring/RiskTrendChart';
import { MultiAgentRiskContributionChart } from '../components/riskScoring/MultiAgentRiskContributionChart';
import { TopPriorityThreatsTable } from '../components/riskScoring/TopPriorityThreatsTable';
import { RiskDetailModal } from '../components/riskScoring/RiskDetailModal';
import { RiskVerificationModal } from '../components/riskScoring/RiskVerificationModal';
import { RiskConfigSandbox } from '../components/riskScoring/RiskConfigSandbox';
import { RISK_CONFIG } from '../services/riskScoring/riskConfig';

export const RiskAnalysisPage: React.FC = () => {
  const [assessments, setAssessments] = useState<RiskAssessment[]>([]);
  const [selectedRisk, setSelectedRisk] = useState<RiskAssessment | null>(null);
  const [isTestModalOpen, setIsTestModalOpen] = useState(false);
  const [currentConfig, setCurrentConfig] = useState<RiskModelConfig>(() => riskService.getRiskConfig());
  const [selectedBandFilter, setSelectedBandFilter] = useState<string | null>(null);

  useEffect(() => {
    async function load() {
      const data = await riskService.getRiskAssessments();
      setAssessments(data);
      if (data.length > 0 && !selectedRisk) {
        setSelectedRisk(data[0]);
      }
    }
    load();
  }, []);

  const handleUpdateStatus = async (id: string, newStatus: RiskStatus) => {
    await riskService.updateAssessmentStatus(id, newStatus);
    const updated = await riskService.getRiskAssessments();
    setAssessments(updated);
    if (selectedRisk && selectedRisk.id === id) {
      const refreshed = updated.find(a => a.id === id);
      if (refreshed) setSelectedRisk(refreshed);
    }
  };

  const handleApplyConfig = async (newConfig: RiskModelConfig) => {
    setCurrentConfig(newConfig);
    const recalculated = await riskService.recalculateWithCustomConfig(newConfig);
    setAssessments(recalculated);
    if (selectedRisk) {
      const refreshed = recalculated.find(a => a.id === selectedRisk.id);
      if (refreshed) setSelectedRisk(refreshed);
    }
  };

  const displayedAssessments = selectedBandFilter
    ? assessments.filter(a => a.riskBand === selectedBandFilter)
    : assessments;

  return (
    <div className="space-y-6" id="page-risk-analysis">
      {/* Header Banner */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 border border-slate-800 rounded-xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
            <span className="text-xs font-mono uppercase tracking-widest text-cyan-400 font-semibold">
              Stage 8: Risk Scoring & Threat Prioritization
            </span>
          </div>
          <h2 className="text-lg sm:text-xl font-bold text-white tracking-tight">
            Deterministic Multi-Factor Risk Scoring Engine
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">
            Synthesizes Threat Severity, ML Confidence, Multi-Agent Correlation Strength, Attack Complexity, Agent Involvement, Evidence Volume, and Impacted Entities into an explainable 0–100 priority index.
          </p>
        </div>

        <div className="flex items-center gap-2 font-mono text-xs self-start md:self-auto">
          <button
            id="btn-run-risk-tests"
            onClick={() => setIsTestModalOpen(true)}
            className="px-3 py-2 rounded-lg bg-indigo-950 hover:bg-indigo-900 text-indigo-200 border border-indigo-700 flex items-center gap-1.5 transition-colors shadow-lg shadow-indigo-950/40"
          >
            <Play className="w-3.5 h-3.5 text-cyan-400" />
            <span>Run 8 Verification Tests</span>
          </button>
        </div>
      </div>

      {/* 1. Risk Overview Cards */}
      <RiskOverviewCards
        assessments={assessments}
        selectedBand={selectedBandFilter}
        onSelectBand={setSelectedBandFilter}
      />

      {/* 2. Visual Distribution & Chronological Trend Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <RiskDistributionChart assessments={displayedAssessments} />
        <RiskTrendChart assessments={displayedAssessments} />
      </div>

      {/* 3. Multi-Agent Contribution Matrix */}
      <MultiAgentRiskContributionChart assessments={displayedAssessments} />

      {/* 4. Configurable Academic/Demo Risk Model Weights Sandbox */}
      <RiskConfigSandbox
        currentConfig={currentConfig}
        onApplyConfig={handleApplyConfig}
      />

      {/* 5. Top Priority Threats Table */}
      <TopPriorityThreatsTable
        assessments={displayedAssessments}
        onSelectAssessment={item => setSelectedRisk(item)}
        onUpdateStatus={handleUpdateStatus}
      />

      {/* 6. Explainable Risk Detail Modal */}
      {selectedRisk && (
        <RiskDetailModal
          assessment={selectedRisk}
          onClose={() => setSelectedRisk(null)}
          onUpdateStatus={handleUpdateStatus}
        />
      )}

      {/* 7. Live 8-Test Verification Modal */}
      <RiskVerificationModal
        isOpen={isTestModalOpen}
        onClose={() => setIsTestModalOpen(false)}
      />
    </div>
  );
};
