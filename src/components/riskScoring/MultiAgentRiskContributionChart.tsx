/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Multi-Agent Risk Contribution Visualizer
 *
 * Demonstrates the multi-agent architecture:
 * - Network Security Agent
 * - System Security Agent
 * - Application Security Agent
 */

import React from 'react';
import { Network, Server, Globe, Shield, Layers, GitMerge } from 'lucide-react';
import { RiskAssessment } from '../../types/riskScoring';

interface MultiAgentRiskContributionChartProps {
  assessments: RiskAssessment[];
}

export const MultiAgentRiskContributionChart: React.FC<MultiAgentRiskContributionChartProps> = ({
  assessments
}) => {
  // Aggregate agent statistics
  let netCount = 0;
  let sysCount = 0;
  let appCount = 0;
  let multiAgentIncidents = 0;
  let totalEvidence = 0;

  assessments.forEach(a => {
    const agents = a.participatingAgents || [];
    if (agents.includes('NETWORK_AGENT')) netCount++;
    if (agents.includes('SYSTEM_AGENT')) sysCount++;
    if (agents.includes('APPLICATION_AGENT')) appCount++;
    if (agents.length >= 2) multiAgentIncidents++;
    totalEvidence += a.evidenceVolume || 1;
  });

  const total = assessments.length || 1;
  const multiAgentRatio = Math.round((multiAgentIncidents / total) * 100);

  return (
    <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-4">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <h4 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            Multi-Agent Risk Contribution Matrix
          </h4>
          <p className="text-[11px] text-slate-400">
            Synthesis of independent evidence channels across the 3 specialized security agents.
          </p>
        </div>

        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-indigo-950/60 border border-indigo-800 text-xs font-mono text-indigo-300">
          <GitMerge className="w-3.5 h-3.5 text-indigo-400" />
          <span>Multi-Agent Ratio: {multiAgentRatio}%</span>
        </div>
      </div>

      {/* 3 Agents Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 font-mono">
        {/* Network Agent */}
        <div className="p-3 bg-slate-950/70 border border-cyan-900/40 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-bold">
              <Network className="w-4 h-4" />
              <span>Network Agent</span>
            </div>
            <span className="text-xs text-slate-400">{netCount}/{total}</span>
          </div>

          <div>
            <div className="flex justify-between text-[11px] text-slate-400 mb-1">
              <span>Threat Presence</span>
              <span className="text-cyan-400 font-bold">{Math.round((netCount / total) * 100)}%</span>
            </div>
            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-cyan-400 transition-all"
                style={{ width: `${(netCount / total) * 100}%` }}
              />
            </div>
          </div>
          <p className="text-[10px] text-slate-500">
            Ingress scans, port sweeps, DNS entropy & volumetric C2 heuristics.
          </p>
        </div>

        {/* System Agent */}
        <div className="p-3 bg-slate-950/70 border border-emerald-900/40 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-bold">
              <Server className="w-4 h-4" />
              <span>System Agent</span>
            </div>
            <span className="text-xs text-slate-400">{sysCount}/{total}</span>
          </div>

          <div>
            <div className="flex justify-between text-[11px] text-slate-400 mb-1">
              <span>Threat Presence</span>
              <span className="text-emerald-400 font-bold">{Math.round((sysCount / total) * 100)}%</span>
            </div>
            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-emerald-400 transition-all"
                style={{ width: `${(sysCount / total) * 100}%` }}
              />
            </div>
          </div>
          <p className="text-[10px] text-slate-500">
            Process tree anomalies, token elevation, temp binary execution & pam logs.
          </p>
        </div>

        {/* Application Agent */}
        <div className="p-3 bg-slate-950/70 border border-purple-900/40 rounded-lg space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-purple-400 text-xs font-bold">
              <Globe className="w-4 h-4" />
              <span>Application Agent</span>
            </div>
            <span className="text-xs text-slate-400">{appCount}/{total}</span>
          </div>

          <div>
            <div className="flex justify-between text-[11px] text-slate-400 mb-1">
              <span>Threat Presence</span>
              <span className="text-purple-400 font-bold">{Math.round((appCount / total) * 100)}%</span>
            </div>
            <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-purple-400 transition-all"
                style={{ width: `${(appCount / total) * 100}%` }}
              />
            </div>
          </div>
          <p className="text-[10px] text-slate-500">
            SQLi payloads, WAF breaches, brute force auth spikes & API bursts.
          </p>
        </div>
      </div>

      {/* Aggregate Architecture Summary Footer */}
      <div className="p-2.5 rounded bg-slate-950/40 border border-slate-800 text-[11px] font-mono text-slate-400 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <Shield className="w-3.5 h-3.5 text-cyan-400" />
          <span>
            Total Corroborated Evidence Artifacts: <strong className="text-white">{totalEvidence}</strong>
          </span>
        </div>
        <div className="text-slate-500">
          Cross-Agent Sequence Escalation Weight: <strong>10%</strong>
        </div>
      </div>
    </div>
  );
};
