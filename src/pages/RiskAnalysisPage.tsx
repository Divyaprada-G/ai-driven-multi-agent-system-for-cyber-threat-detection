import React, { useState, useEffect } from 'react';
import { Activity, ShieldCheck, AlertTriangle, ArrowUpRight, CheckCircle2, SlidersHorizontal } from 'lucide-react';
import { RiskAssessment, SeverityLevel } from '../types';
import { riskService } from '../services/riskService';
import { SeverityBadge } from '../components/common/SeverityBadge';

export const RiskAnalysisPage: React.FC = () => {
  const [assessments, setAssessments] = useState<RiskAssessment[]>([]);
  const [selectedRisk, setSelectedRisk] = useState<RiskAssessment | null>(null);

  // Dynamic Risk Calculator Sandbox
  const [factors, setFactors] = useState({
    assetCriticality: 85,
    exploitability: 80,
    lateralMovementPotential: 75,
    dataLossExposure: 70
  });
  const [calculatedResult, setCalculatedResult] = useState<{ score: number; severity: SeverityLevel }>({
    score: 79,
    severity: 'HIGH'
  });

  useEffect(() => {
    async function load() {
      const data = await riskService.getRiskAssessments();
      setAssessments(data);
      if (data.length > 0) {
        setSelectedRisk(data[0]);
      }
    }
    load();
  }, []);

  const handleRecalculate = async (newFactors: typeof factors) => {
    setFactors(newFactors);
    const res = await riskService.calculateRiskScore(newFactors);
    setCalculatedResult(res);
  };

  return (
    <div className="space-y-6" id="page-risk-analysis">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest">
            Quantitative Impact Triage
          </span>
        </div>
        <h2 className="text-xl font-bold text-white tracking-tight">
          Risk Analysis & Scoring Matrix
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          Multi-variable quantitative risk computation prioritizing incidents based on asset criticality, vulnerability exploitability, potential for lateral compromise, and sensitive data loss risk.
        </p>
      </div>

      {/* Severity Reference Levels Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="p-3.5 bg-blue-950/20 border border-blue-800/40 rounded-xl font-mono">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-blue-400">LOW SEVERITY</span>
            <span className="text-xs text-slate-400">0 - 49 pts</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Standard reconnaissance or low-impact anomalies requiring passive telemetry tracking.
          </p>
        </div>

        <div className="p-3.5 bg-amber-950/20 border border-amber-800/40 rounded-xl font-mono">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-amber-400">MEDIUM SEVERITY</span>
            <span className="text-xs text-slate-400">50 - 74 pts</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Suspicious authentication spikes, rate anomalies, or unvalidated parameter tampering.
          </p>
        </div>

        <div className="p-3.5 bg-orange-950/20 border border-orange-800/40 rounded-xl font-mono">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-orange-400">HIGH SEVERITY</span>
            <span className="text-xs text-slate-400">75 - 89 pts</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Active exploitation signatures (SQLi, brute force, reverse shells) against vital assets.
          </p>
        </div>

        <div className="p-3.5 bg-rose-950/20 border border-rose-800/40 rounded-xl font-mono">
          <div className="flex items-center justify-between">
            <span className="text-xs font-bold text-rose-400">CRITICAL SEVERITY</span>
            <span className="text-xs text-slate-400">90 - 100 pts</span>
          </div>
          <p className="text-[11px] text-slate-400 mt-1">
            Confirmed privilege escalation or ongoing data exfiltration on mission-critical hosts.
          </p>
        </div>
      </div>

      {/* Interactive Risk Calculation Model Sandbox */}
      <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-xl space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <SlidersHorizontal className="w-4 h-4 text-cyan-400" />
              Risk Scoring Engine Factor Weighting
            </h3>
            <p className="text-xs text-slate-400">
              Adjust variables to test multi-agent risk evaluation formula.
            </p>
          </div>
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-slate-400">Computed Result:</span>
            <span className="text-lg font-bold font-mono text-white">{calculatedResult.score}/100</span>
            <SeverityBadge severity={calculatedResult.severity} size="md" />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 font-mono text-xs">
          <div>
            <div className="flex justify-between mb-1 text-slate-300">
              <span>Asset Criticality</span>
              <span className="text-cyan-400 font-bold">{factors.assetCriticality}%</span>
            </div>
            <input
              type="range"
              min="0"
              max="100"
              value={factors.assetCriticality}
              onChange={e => handleRecalculate({ ...factors, assetCriticality: Number(e.target.value) })}
              className="w-full accent-cyan-400"
            />
          </div>

          <div>
            <div className="flex justify-between mb-1 text-slate-300">
              <span>Exploitability</span>
              <span className="text-cyan-400 font-bold">{factors.exploitability}%</span>
            </div>
            <input
              type="range"
              min="0"
              max="100"
              value={factors.exploitability}
              onChange={e => handleRecalculate({ ...factors, exploitability: Number(e.target.value) })}
              className="w-full accent-cyan-400"
            />
          </div>

          <div>
            <div className="flex justify-between mb-1 text-slate-300">
              <span>Lateral Movement</span>
              <span className="text-cyan-400 font-bold">{factors.lateralMovementPotential}%</span>
            </div>
            <input
              type="range"
              min="0"
              max="100"
              value={factors.lateralMovementPotential}
              onChange={e => handleRecalculate({ ...factors, lateralMovementPotential: Number(e.target.value) })}
              className="w-full accent-cyan-400"
            />
          </div>

          <div>
            <div className="flex justify-between mb-1 text-slate-300">
              <span>Data Loss Exposure</span>
              <span className="text-cyan-400 font-bold">{factors.dataLossExposure}%</span>
            </div>
            <input
              type="range"
              min="0"
              max="100"
              value={factors.dataLossExposure}
              onChange={e => handleRecalculate({ ...factors, dataLossExposure: Number(e.target.value) })}
              className="w-full accent-cyan-400"
            />
          </div>
        </div>
      </div>

      {/* Risk Assessments Table */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800">
          <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            Evaluated Risk Assessments
          </h3>
          <p className="text-xs text-slate-400">
            Automated assessments synthesized across all ingested telemetry.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Risk ID</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Threat Category</th>
                <th className="py-3 px-4">Affected Source</th>
                <th className="py-3 px-4">Recommended Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {assessments.map(item => (
                <tr
                  key={item.id}
                  id={`row-risk-${item.id.toLowerCase()}`}
                  onClick={() => setSelectedRisk(item)}
                  className={`cursor-pointer transition-colors ${
                    selectedRisk?.id === item.id ? 'bg-slate-800/60' : 'hover:bg-slate-800/30'
                  }`}
                >
                  <td className="py-3 px-4 font-bold text-cyan-400">{item.id}</td>

                  <td className="py-3 px-4">
                    <span
                      className={`text-sm font-bold ${
                        item.score >= 90
                          ? 'text-rose-400'
                          : item.score >= 75
                          ? 'text-orange-400'
                          : item.score >= 50
                          ? 'text-amber-400'
                          : 'text-blue-400'
                      }`}
                    >
                      {item.score}/100
                    </span>
                  </td>

                  <td className="py-3 px-4">
                    <SeverityBadge severity={item.severity} />
                  </td>

                  <td className="py-3 px-4 text-emerald-400">{item.confidence}%</td>

                  <td className="py-3 px-4 font-sans font-medium text-slate-100">
                    {item.threatCategory}
                  </td>

                  <td className="py-3 px-4 text-slate-300 max-w-[180px] truncate">
                    {item.affectedSource}
                  </td>

                  <td className="py-3 px-4 font-sans text-slate-400 max-w-[240px] truncate">
                    {item.recommendedAction}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail View for Selected Risk Item */}
      {selectedRisk && (
        <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
            <div>
              <div className="text-xs font-mono text-cyan-400">{selectedRisk.id} Remediation Directive</div>
              <h3 className="text-base font-bold text-white mt-0.5">{selectedRisk.threatCategory}</h3>
            </div>
            <SeverityBadge severity={selectedRisk.severity} size="md" />
          </div>

          <div className="space-y-2">
            <h4 className="text-xs font-mono uppercase tracking-wider text-slate-400">
              Recommended Remediation Playbook (Prepared for n8n automation)
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {selectedRisk.remediationPlan.map((step, idx) => (
                <div
                  key={idx}
                  className="p-3 bg-slate-950/80 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 flex items-start gap-2"
                >
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                  <span>{step}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
