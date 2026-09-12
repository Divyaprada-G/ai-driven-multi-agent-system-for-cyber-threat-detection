/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Chronological Risk Trend Visualizer
 *
 * NOTE: Strictly visualizes real available assessed data over chronological
 * timeline. Never fabricates synthetic historical points.
 */

import React from 'react';
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';
import { TrendingUp, TrendingDown, Minus } from 'lucide-react';
import { RiskAssessment } from '../../types/riskScoring';

interface RiskTrendChartProps {
  assessments: RiskAssessment[];
  height?: number;
}

export const RiskTrendChart: React.FC<RiskTrendChartProps> = ({
  assessments,
  height = 200
}) => {
  // Sort chronologically based only on available data
  const chronological = [...assessments].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );

  const chartData = chronological.map((item, idx) => ({
    id: item.id,
    time: item.timestamp.includes('T')
      ? item.timestamp.split('T')[1].substring(0, 8)
      : item.timestamp.split(' ')[1] || `T+${idx}`,
    score: item.riskScore,
    priority: item.priority,
    band: item.riskBand,
    classification: String(item.threatClassification)
  }));

  // Calculate trend direction (Increasing / Decreasing / Stable)
  let trend: 'INCREASING' | 'DECREASING' | 'STABLE' = 'STABLE';
  if (chartData.length >= 2) {
    const firstHalf = chartData.slice(0, Math.floor(chartData.length / 2));
    const secondHalf = chartData.slice(Math.floor(chartData.length / 2));

    const avgFirst = firstHalf.reduce((acc, i) => acc + i.score, 0) / (firstHalf.length || 1);
    const avgSecond = secondHalf.reduce((acc, i) => acc + i.score, 0) / (secondHalf.length || 1);

    const diff = avgSecond - avgFirst;
    if (diff > 5) trend = 'INCREASING';
    else if (diff < -5) trend = 'DECREASING';
    else trend = 'STABLE';
  }

  return (
    <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h4 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            Chronological Risk Trend
          </h4>
          <p className="text-[11px] text-slate-400">
            Assessed risk progression across ingested event sequence.
          </p>
        </div>

        {/* Dynamic Trend Badge */}
        <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-950 border border-slate-800 text-xs font-mono">
          <span className="text-slate-400">Velocity:</span>
          {trend === 'INCREASING' && (
            <span className="text-rose-400 flex items-center gap-1 font-bold">
              <TrendingUp className="w-3.5 h-3.5" /> INCREASING
            </span>
          )}
          {trend === 'DECREASING' && (
            <span className="text-emerald-400 flex items-center gap-1 font-bold">
              <TrendingDown className="w-3.5 h-3.5" /> DECREASING
            </span>
          )}
          {trend === 'STABLE' && (
            <span className="text-cyan-400 flex items-center gap-1 font-bold">
              <Minus className="w-3.5 h-3.5" /> STABLE
            </span>
          )}
        </div>
      </div>

      <div style={{ width: '100%', height }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
            <XAxis
              dataKey="time"
              stroke="#64748b"
              fontSize={10}
              tickLine={false}
            />
            <YAxis
              domain={[0, 100]}
              stroke="#64748b"
              fontSize={10}
              tickLine={false}
              ticks={[0, 30, 60, 80, 100]}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const item = payload[0].payload;
                  return (
                    <div className="p-2.5 bg-slate-950 border border-slate-700 rounded-lg shadow-xl font-mono text-xs space-y-1">
                      <div className="text-cyan-400 font-bold">{item.id}</div>
                      <div className="text-white font-bold">
                        Score: {item.score}/100 ({item.band} • {item.priority})
                      </div>
                      <div className="text-slate-400 text-[11px] truncate max-w-[200px]">
                        {item.classification}
                      </div>
                      <div className="text-slate-500 text-[10px]">Timestamp: {item.time}</div>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Line
              type="monotone"
              dataKey="score"
              stroke="#06b6d4"
              strokeWidth={2.5}
              dot={{ r: 4, fill: '#06b6d4', stroke: '#083344', strokeWidth: 1.5 }}
              activeDot={{ r: 6, fill: '#22d3ee' }}
            />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="flex items-center justify-between text-[11px] font-mono text-slate-500 pt-1">
        <span>Oldest: {chartData[0]?.time || 'T0'}</span>
        <span>Latest: {chartData[chartData.length - 1]?.time || 'Now'}</span>
      </div>
    </div>
  );
};
