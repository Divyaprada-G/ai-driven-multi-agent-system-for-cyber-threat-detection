/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Threat Analytics & Trend Panel
 *
 * Implements:
 * - Section 5: Threat classification distribution (standard 10 classes)
 * - Section 6: Time-based threat trend (24H, 7D, 30D, ALL) with honest empty state
 * - Section 44: Threat Detection Quality (evaluation metrics or explicit "not available" state)
 */

import React, { useState } from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell,
  CartesianGrid
} from 'recharts';
import { ShieldAlert, TrendingUp, Cpu, Info, CheckCircle2, AlertCircle } from 'lucide-react';
import { ThreatClassificationCount, ThreatTrendDataPoint } from '../../services/unifiedAnalyticsService';
import { TimeRangeFilter } from '../../types/analytics';

interface ThreatAnalyticsPanelProps {
  classifications: ThreatClassificationCount[];
  trend: ThreatTrendDataPoint[];
  hasHistoricalData: boolean;
  activeTimeRange: TimeRangeFilter;
  onTimeRangeChange: (range: TimeRangeFilter) => void;
  evaluationMetrics?: {
    accuracy?: number;
    precision?: number;
    recall?: number;
    f1Score?: number;
    isAvailable: boolean;
  };
}

export const ThreatAnalyticsPanel: React.FC<ThreatAnalyticsPanelProps> = ({
  classifications,
  trend,
  hasHistoricalData,
  activeTimeRange,
  onTimeRangeChange,
  evaluationMetrics
}) => {
  const [chartView, setChartView] = useState<'BAR' | 'DONUT'>('BAR');

  const activeClassifications = classifications.filter(c => c.count > 0);

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Classification Distribution (7 cols) */}
        <div className="lg:col-span-7 p-4 bg-slate-900 border border-slate-800 rounded-xl shadow space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold font-mono text-white">
                Threat Classification Distribution
              </h3>
            </div>
            <div className="flex items-center gap-1 bg-slate-950 p-1 border border-slate-800 rounded-lg text-[10px] font-mono">
              <button
                onClick={() => setChartView('BAR')}
                className={`px-2 py-0.5 rounded transition-colors ${
                  chartView === 'BAR'
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Bar
              </button>
              <button
                onClick={() => setChartView('DONUT')}
                className={`px-2 py-0.5 rounded transition-colors ${
                  chartView === 'DONUT'
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                Donut
              </button>
            </div>
          </div>

          {activeClassifications.length === 0 ? (
            <div className="py-12 text-center text-slate-500 font-mono text-xs">
              No threat detections classified in active dataset.
            </div>
          ) : chartView === 'BAR' ? (
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={activeClassifications}
                  layout="vertical"
                  margin={{ top: 5, right: 30, left: 40, bottom: 5 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis type="number" stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
                  <YAxis
                    type="category"
                    dataKey="displayName"
                    stroke="#94a3b8"
                    width={130}
                    tick={{ fontSize: 10, fill: '#cbd5e1' }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '11px',
                      fontFamily: 'monospace'
                    }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {activeClassifications.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="h-64 w-full flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={activeClassifications}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={3}
                    dataKey="count"
                    nameKey="displayName"
                  >
                    {activeClassifications.map((entry, index) => (
                      <Cell key={`donut-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '11px',
                      fontFamily: 'monospace'
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Classification Pills */}
          <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-800/80">
            {classifications.map(c => (
              <div
                key={c.classification}
                className="flex items-center gap-1.5 px-2 py-1 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono"
              >
                <span
                  className="w-2 h-2 rounded-full"
                  style={{ backgroundColor: c.color }}
                />
                <span className="text-slate-300">{c.displayName}:</span>
                <span className="text-white font-bold">{c.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Time-Based Threat Trend Chart (5 cols) */}
        <div className="lg:col-span-5 p-4 bg-slate-900 border border-slate-800 rounded-xl shadow space-y-3 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-emerald-400" />
                <h3 className="text-sm font-bold font-mono text-white">Threat Trend</h3>
              </div>

              {/* Time Range Selector */}
              <div className="flex items-center gap-1 bg-slate-950 p-1 border border-slate-800 rounded-lg text-[10px] font-mono">
                {(['24H', '7D', '30D', 'ALL'] as TimeRangeFilter[]).map(r => (
                  <button
                    key={r}
                    onClick={() => onTimeRangeChange(r)}
                    className={`px-1.5 py-0.5 rounded transition-colors ${
                      activeTimeRange === r
                        ? 'bg-emerald-500/20 text-emerald-300 font-bold'
                        : 'text-slate-400 hover:text-white'
                    }`}
                  >
                    {r}
                  </button>
                ))}
              </div>
            </div>

            <p className="text-[11px] text-slate-400 font-mono mt-1">
              Detected threats plotted across timestamp progression.
            </p>
          </div>

          {!hasHistoricalData || trend.length === 0 ? (
            <div className="h-56 flex flex-col items-center justify-center text-center p-6 bg-slate-950/60 rounded-lg border border-dashed border-slate-800 text-slate-500 font-mono text-xs space-y-2">
              <AlertCircle className="w-6 h-6 text-slate-600" />
              <span>No historical threat data available.</span>
              <span className="text-[10px] text-slate-600">
                Threat events will populate trend telemetry dynamically upon detection.
              </span>
            </div>
          ) : (
            <div className="h-56 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={trend} margin={{ top: 10, right: 20, left: -20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="formattedTime"
                    stroke="#64748b"
                    tick={{ fontSize: 9, fill: '#64748b' }}
                  />
                  <YAxis stroke="#64748b" tick={{ fontSize: 9, fill: '#64748b' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '11px',
                      fontFamily: 'monospace'
                    }}
                  />
                  <Line
                    type="monotone"
                    dataKey="threatCount"
                    stroke="#38bdf8"
                    strokeWidth={2}
                    dot={{ fill: '#38bdf8', r: 3 }}
                    name="Threat Events"
                  />
                  <Line
                    type="monotone"
                    dataKey="criticalCount"
                    stroke="#ef4444"
                    strokeWidth={2}
                    dot={{ fill: '#ef4444', r: 3 }}
                    name="Critical"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* Model Evaluation Quality Card (Section 44) */}
          <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-slate-400">
                <Cpu className="w-3.5 h-3.5 text-indigo-400" />
                <span className="text-[10px] uppercase font-bold">Threat Detection Quality</span>
              </div>
              {evaluationMetrics?.isAvailable ? (
                <span className="px-2 py-0.5 rounded text-[9px] bg-emerald-950 text-emerald-300 border border-emerald-800 font-bold">
                  EVALUATED
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded text-[9px] bg-slate-800 text-slate-400 border border-slate-700 font-bold">
                  PENDING TRAINING
                </span>
              )}
            </div>

            {evaluationMetrics?.isAvailable ? (
              <div className="grid grid-cols-4 gap-2 mt-2 text-center">
                <div className="p-1.5 bg-slate-900 rounded border border-slate-800">
                  <span className="text-[9px] text-slate-500 block">Accuracy</span>
                  <span className="text-xs font-bold text-cyan-400">
                    {(evaluationMetrics.accuracy! * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="p-1.5 bg-slate-900 rounded border border-slate-800">
                  <span className="text-[9px] text-slate-500 block">Precision</span>
                  <span className="text-xs font-bold text-emerald-400">
                    {(evaluationMetrics.precision! * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="p-1.5 bg-slate-900 rounded border border-slate-800">
                  <span className="text-[9px] text-slate-500 block">Recall</span>
                  <span className="text-xs font-bold text-amber-400">
                    {(evaluationMetrics.recall! * 100).toFixed(1)}%
                  </span>
                </div>
                <div className="p-1.5 bg-slate-900 rounded border border-slate-800">
                  <span className="text-[9px] text-slate-500 block">F1-Score</span>
                  <span className="text-xs font-bold text-indigo-400">
                    {(evaluationMetrics.f1Score! * 100).toFixed(1)}%
                  </span>
                </div>
              </div>
            ) : (
              <p className="text-[11px] text-slate-500 mt-2 italic">
                Model evaluation metrics not available yet. Connect pre-trained weights or run evaluation dataset.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
