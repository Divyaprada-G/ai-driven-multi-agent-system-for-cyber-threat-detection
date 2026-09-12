/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Risk Overview Metrics Summary Cards
 */

import React from 'react';
import { ShieldAlert, Flame, AlertTriangle, ShieldCheck, Activity, Info } from 'lucide-react';
import { RiskAssessment } from '../../types/riskScoring';

interface RiskOverviewCardsProps {
  assessments: RiskAssessment[];
  onSelectBand?: (band: string | null) => void;
  selectedBand?: string | null;
}

export const RiskOverviewCards: React.FC<RiskOverviewCardsProps> = ({
  assessments,
  onSelectBand,
  selectedBand
}) => {
  const total = assessments.length;
  const critical = assessments.filter(a => a.riskBand === 'CRITICAL').length;
  const high = assessments.filter(a => a.riskBand === 'HIGH').length;
  const medium = assessments.filter(a => a.riskBand === 'MEDIUM').length;
  const low = assessments.filter(a => a.riskBand === 'LOW').length;

  const avgScore =
    total > 0
      ? Math.round(assessments.reduce((acc, a) => acc + a.riskScore, 0) / total)
      : 0;

  return (
    <div className="space-y-3" id="section-risk-overview">
      {/* Configuration & Model Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 p-3 bg-slate-900/60 border border-slate-800 rounded-lg text-xs font-mono">
        <div className="flex items-center gap-2 text-slate-300">
          <Activity className="w-4 h-4 text-cyan-400" />
          <span className="font-bold text-white">Engine Model:</span>
          <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800">
            Configurable Academic/Demo Risk Model (v1.0)
          </span>
          <span className="hidden md:inline text-slate-500">|</span>
          <span className="text-slate-400">Avg Risk:</span>
          <span className="font-bold text-white">{avgScore}/100</span>
        </div>

        <div className="flex items-center gap-1.5 text-[11px] text-slate-400">
          <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
          <span>Risk bands are configurable academic/demo thresholds.</span>
        </div>
      </div>

      {/* Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {/* Total Threats */}
        <div
          onClick={() => onSelectBand && onSelectBand(null)}
          className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
            selectedBand === null
              ? 'bg-slate-800/90 border-cyan-500/80 shadow-lg shadow-cyan-900/20'
              : 'bg-slate-900/70 border-slate-800 hover:border-slate-700'
          }`}
        >
          <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
            <span>Total Evaluated</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold text-white font-mono mt-1">{total}</div>
          <div className="text-[10px] text-slate-400 font-mono mt-0.5">Triaged correlations</div>
        </div>

        {/* Critical (P1) */}
        <div
          onClick={() => onSelectBand && onSelectBand(selectedBand === 'CRITICAL' ? null : 'CRITICAL')}
          className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
            selectedBand === 'CRITICAL'
              ? 'bg-rose-950/60 border-rose-500 shadow-lg shadow-rose-900/20'
              : 'bg-rose-950/20 border-rose-900/40 hover:border-rose-700/60'
          }`}
        >
          <div className="flex items-center justify-between text-xs text-rose-300 font-mono">
            <span className="font-bold">CRITICAL (P1)</span>
            <Flame className="w-4 h-4 text-rose-400 animate-pulse" />
          </div>
          <div className="text-2xl font-bold text-rose-400 font-mono mt-1">{critical}</div>
          <div className="text-[10px] text-rose-400/80 font-mono mt-0.5">81–100 pts • Escalate</div>
        </div>

        {/* High (P2) */}
        <div
          onClick={() => onSelectBand && onSelectBand(selectedBand === 'HIGH' ? null : 'HIGH')}
          className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
            selectedBand === 'HIGH'
              ? 'bg-orange-950/60 border-orange-500 shadow-lg shadow-orange-900/20'
              : 'bg-orange-950/20 border-orange-900/40 hover:border-orange-700/60'
          }`}
        >
          <div className="flex items-center justify-between text-xs text-orange-300 font-mono">
            <span className="font-bold">HIGH (P2)</span>
            <ShieldAlert className="w-4 h-4 text-orange-400" />
          </div>
          <div className="text-2xl font-bold text-orange-400 font-mono mt-1">{high}</div>
          <div className="text-[10px] text-orange-400/80 font-mono mt-0.5">61–80 pts • Investigate</div>
        </div>

        {/* Medium (P3) */}
        <div
          onClick={() => onSelectBand && onSelectBand(selectedBand === 'MEDIUM' ? null : 'MEDIUM')}
          className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
            selectedBand === 'MEDIUM'
              ? 'bg-amber-950/60 border-amber-500 shadow-lg shadow-amber-900/20'
              : 'bg-amber-950/20 border-amber-900/40 hover:border-amber-700/60'
          }`}
        >
          <div className="flex items-center justify-between text-xs text-amber-300 font-mono">
            <span className="font-bold">MEDIUM (P3)</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold text-amber-400 font-mono mt-1">{medium}</div>
          <div className="text-[10px] text-amber-400/80 font-mono mt-0.5">31–60 pts • Verify</div>
        </div>

        {/* Low (P4) */}
        <div
          onClick={() => onSelectBand && onSelectBand(selectedBand === 'LOW' ? null : 'LOW')}
          className={`p-3.5 rounded-xl border transition-all cursor-pointer ${
            selectedBand === 'LOW'
              ? 'bg-blue-950/60 border-blue-500 shadow-lg shadow-blue-900/20'
              : 'bg-blue-950/20 border-blue-900/40 hover:border-blue-700/60'
          }`}
        >
          <div className="flex items-center justify-between text-xs text-blue-300 font-mono">
            <span className="font-bold">LOW (P4)</span>
            <ShieldCheck className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-blue-400 font-mono mt-1">{low}</div>
          <div className="text-[10px] text-blue-400/80 font-mono mt-0.5">0–30 pts • Monitor</div>
        </div>
      </div>
    </div>
  );
};
