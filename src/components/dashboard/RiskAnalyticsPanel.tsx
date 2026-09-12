/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Risk Analytics, Distribution & Top Risk Events Panel
 *
 * Implements:
 * - Section 7: Quantitative metrics (Average Score, Highest Score, Counts)
 * - Section 8: Risk distribution across 4 strict severity tiers
 * - Section 9: Risk Score Trend visualization with direction detection
 * - Section 10: Top Risk Events table with rank, priority, and detail click handler
 */

import React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Cell
} from 'recharts';
import {
  Flame,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  Minus,
  HelpCircle,
  Shield,
  Layers,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import { RiskAnalyticsData } from '../../services/unifiedAnalyticsService';
import { RiskAssessment } from '../../types/riskScoring';
import { SeverityBadge } from '../common/SeverityBadge';

interface RiskAnalyticsPanelProps {
  riskData: RiskAnalyticsData;
  assessments: RiskAssessment[];
  onSelectRisk: (assessment: RiskAssessment) => void;
}

export const RiskAnalyticsPanel: React.FC<RiskAnalyticsPanelProps> = ({
  riskData,
  assessments,
  onSelectRisk
}) => {
  // Sort assessments by highest risk score first (Section 10)
  const sortedTopRisks = [...assessments].sort((a, b) => b.riskScore - a.riskScore).slice(0, 5);

  const getTrendIcon = (direction: string) => {
    switch (direction) {
      case 'INCREASING':
        return (
          <span className="flex items-center gap-1 text-rose-400 font-bold">
            <TrendingUp className="w-3.5 h-3.5" /> Increasing Risk
          </span>
        );
      case 'DECREASING':
        return (
          <span className="flex items-center gap-1 text-emerald-400 font-bold">
            <TrendingDown className="w-3.5 h-3.5" /> Decreasing Risk
          </span>
        );
      case 'STABLE':
        return (
          <span className="flex items-center gap-1 text-cyan-400 font-bold">
            <Minus className="w-3.5 h-3.5" /> Stable Baseline
          </span>
        );
      case 'INSUFFICIENT_DATA':
      default:
        return (
          <span className="flex items-center gap-1 text-slate-500 italic">
            <HelpCircle className="w-3.5 h-3.5" /> Insufficient data for trend analysis
          </span>
        );
    }
  };

  const getPriorityStyle = (priority: string) => {
    switch (priority) {
      case 'P1':
        return 'bg-rose-950 text-rose-300 border-rose-800';
      case 'P2':
        return 'bg-orange-950 text-orange-300 border-orange-800';
      case 'P3':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'P4':
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Key Quantitative Metrics (Section 7) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 shadow">
          <span className="text-[10px] text-slate-500 uppercase font-mono block">Average Risk Score</span>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
            {riskData.averageRiskScore}
            <span className="text-xs text-slate-500 font-normal"> / 100</span>
          </div>
          <span className="text-[9px] text-slate-500 font-mono mt-0.5 block">7-Factor Mean</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 shadow">
          <span className="text-[10px] text-slate-500 uppercase font-mono block">Highest Risk Score</span>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-1">
            {riskData.highestRiskScore}
            <span className="text-xs text-slate-500 font-normal"> / 100</span>
          </div>
          <span className="text-[9px] text-rose-500/80 font-mono mt-0.5 block">Peak Exposure</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 shadow">
          <span className="text-[10px] text-slate-500 uppercase font-mono block">Critical (80-100)</span>
          <div className="text-2xl font-bold font-mono text-rose-500 mt-1">
            {riskData.criticalRiskCount}
          </div>
          <span className="text-[9px] text-slate-500 font-mono mt-0.5 block">P1 Escalation</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 shadow">
          <span className="text-[10px] text-slate-500 uppercase font-mono block">High (60-79)</span>
          <div className="text-2xl font-bold font-mono text-orange-400 mt-1">
            {riskData.highRiskCount}
          </div>
          <span className="text-[9px] text-slate-500 font-mono mt-0.5 block">P2 Priority</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 shadow">
          <span className="text-[10px] text-slate-500 uppercase font-mono block">Medium (40-59)</span>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">
            {riskData.mediumRiskCount}
          </div>
          <span className="text-[9px] text-slate-500 font-mono mt-0.5 block">P3 Monitoring</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 shadow">
          <span className="text-[10px] text-slate-500 uppercase font-mono block">Low (0-39)</span>
          <div className="text-2xl font-bold font-mono text-blue-400 mt-1">
            {riskData.lowRiskCount}
          </div>
          <span className="text-[9px] text-slate-500 font-mono mt-0.5 block">P4 Baseline</span>
        </div>
      </div>

      {/* Middle Row: Distribution & Score Trend */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Risk Distribution Chart (Section 8) */}
        <div className="lg:col-span-6 p-4 bg-slate-900 border border-slate-800 rounded-xl shadow space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Flame className="w-4 h-4 text-orange-400" />
              <h3 className="text-sm font-bold font-mono text-white">
                Risk Score Distribution
              </h3>
            </div>
            <span className="text-[10px] font-mono text-slate-500">
              Total Evaluated: {assessments.length}
            </span>
          </div>

          <div className="h-52 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskData.riskDistribution} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="level" stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                    fontFamily: 'monospace'
                  }}
                  formatter={(value: any, name: any, props: any) => [
                    `${value} event(s) (${props.payload.percentage}%)`,
                    `Range: ${props.payload.range}`
                  ]}
                />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {riskData.riskDistribution.map((entry, index) => (
                    <Cell key={`bar-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-4 gap-2 pt-2 border-t border-slate-800 text-center font-mono">
            {riskData.riskDistribution.map(d => (
              <div key={d.level} className="p-2 rounded bg-slate-950 border border-slate-800/80">
                <span className="text-[9px] text-slate-500 block">{d.level}</span>
                <span className="text-xs font-bold" style={{ color: d.color }}>{d.count} ({d.percentage}%)</span>
              </div>
            ))}
          </div>
        </div>

        {/* Risk Score Trend Visualization (Section 9) */}
        <div className="lg:col-span-6 p-4 bg-slate-900 border border-slate-800 rounded-xl shadow space-y-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold font-mono text-white">Risk Score Trend</h3>
              </div>
              <div className="text-xs font-mono">
                {getTrendIcon(riskData.trendDirection)}
              </div>
            </div>
            <p className="text-[11px] text-slate-400 font-mono mt-1">
              Evaluated risk scores over consecutive event assessments.
            </p>
          </div>

          {riskData.riskScoreTrend.length === 0 ? (
            <div className="h-52 flex flex-col items-center justify-center text-center p-6 bg-slate-950/60 rounded-lg border border-dashed border-slate-800 text-slate-500 font-mono text-xs">
              <HelpCircle className="w-6 h-6 text-slate-600 mb-1" />
              Insufficient data for trend analysis.
            </div>
          ) : (
            <div className="h-52 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={riskData.riskScoreTrend} margin={{ top: 10, right: 20, left: -25, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="id"
                    stroke="#64748b"
                    tick={{ fontSize: 9, fill: '#64748b' }}
                  />
                  <YAxis domain={[0, 100]} stroke="#64748b" tick={{ fontSize: 9, fill: '#64748b' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '11px',
                      fontFamily: 'monospace'
                    }}
                    formatter={(value: any, name: any, props: any) => [
                      `${value}/100 (${props.payload.priority})`,
                      props.payload.threatClass
                    ]}
                  />
                  <Line
                    type="monotone"
                    dataKey="riskScore"
                    stroke="#f97316"
                    strokeWidth={2}
                    dot={{ fill: '#f97316', r: 4 }}
                    name="Risk Score"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          <div className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-[11px] font-mono text-slate-400 flex items-center justify-between">
            <span>Assessment Model: <strong className="text-white">7-Factor Weighted Formula</strong></span>
            <span>Threshold: <strong className="text-rose-400">Score &gt;= 80 triggers P1</strong></span>
          </div>
        </div>
      </div>

      {/* Bottom: Top Risk Events Table (Section 10) */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Flame className="w-4 h-4 text-rose-500" />
            <h3 className="text-sm font-bold font-mono text-white">
              Top Priority Risk Events (Ranked by Risk Score)
            </h3>
          </div>
          <span className="text-[10px] font-mono text-slate-500">
            Sorted: Highest Risk Score First
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="py-2.5 px-3">Rank</th>
                <th className="py-2.5 px-3">Risk Assessment ID</th>
                <th className="py-2.5 px-3">Risk Score</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3">Priority</th>
                <th className="py-2.5 px-3">Threat Classification</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {sortedTopRisks.map((assessment, idx) => (
                <tr
                  key={assessment.id}
                  onClick={() => onSelectRisk(assessment)}
                  className="hover:bg-slate-800/50 cursor-pointer transition-colors group"
                >
                  <td className="py-3 px-3 font-bold text-slate-400">#{idx + 1}</td>
                  <td className="py-3 px-3 text-cyan-400 font-bold">{assessment.id}</td>
                  <td className="py-3 px-3">
                    <span className="text-base font-bold text-rose-400">
                      {assessment.riskScore}
                    </span>
                    <span className="text-slate-500 text-[10px]"> / 100</span>
                  </td>
                  <td className="py-3 px-3">
                    <SeverityBadge severity={assessment.severity} />
                  </td>
                  <td className="py-3 px-3">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold border ${getPriorityStyle(assessment.priority)}`}>
                      {assessment.priority}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-white font-medium">
                    {assessment.threatClassification}
                  </td>
                  <td className="py-3 px-3">
                    <span className="px-2 py-0.5 rounded text-[10px] bg-slate-950 border border-slate-700 text-slate-300">
                      {assessment.status || 'EVALUATED'}
                    </span>
                  </td>
                  <td className="py-3 px-3 text-right">
                    <button className="px-2.5 py-1 rounded bg-slate-800 group-hover:bg-cyan-950 text-slate-300 group-hover:text-cyan-300 border border-slate-700 group-hover:border-cyan-700 text-[10px] font-bold transition-colors inline-flex items-center gap-1">
                      <span>Inspect</span>
                      <ChevronRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
