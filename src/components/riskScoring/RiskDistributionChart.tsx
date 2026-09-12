/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Risk Distribution Visualizer (Recharts)
 */

import React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  Cell
} from 'recharts';
import { RiskAssessment } from '../../types/riskScoring';

interface RiskDistributionChartProps {
  assessments: RiskAssessment[];
  height?: number;
}

export const RiskDistributionChart: React.FC<RiskDistributionChartProps> = ({
  assessments,
  height = 200
}) => {
  const critical = assessments.filter(a => a.riskBand === 'CRITICAL').length;
  const high = assessments.filter(a => a.riskBand === 'HIGH').length;
  const medium = assessments.filter(a => a.riskBand === 'MEDIUM').length;
  const low = assessments.filter(a => a.riskBand === 'LOW').length;

  const data = [
    { band: 'LOW', priority: 'P4', count: low, range: '0–30', color: '#3b82f6' },
    { band: 'MEDIUM', priority: 'P3', count: medium, range: '31–60', color: '#f59e0b' },
    { band: 'HIGH', priority: 'P2', count: high, range: '61–80', color: '#f97316' },
    { band: 'CRITICAL', priority: 'P1', count: critical, range: '81–100', color: '#f43f5e' }
  ];

  const total = assessments.length || 1;

  return (
    <div className="p-4 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h4 className="text-sm font-bold text-white font-mono">
            Risk Tier Distribution
          </h4>
          <p className="text-[11px] text-slate-400">
            Categorized by academic/demo risk thresholds.
          </p>
        </div>
        <span className="text-[11px] font-mono text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-2 py-0.5 rounded">
          {assessments.length} Total
        </span>
      </div>

      <div style={{ width: '100%', height }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <XAxis
              dataKey="band"
              stroke="#64748b"
              fontSize={11}
              tickLine={false}
              tickFormatter={(val, idx) => `${val} (${data[idx].priority})`}
            />
            <YAxis
              stroke="#64748b"
              fontSize={11}
              tickLine={false}
              allowDecimals={false}
            />
            <Tooltip
              content={({ active, payload }) => {
                if (active && payload && payload.length) {
                  const item = payload[0].payload;
                  const pct = Math.round((item.count / total) * 100);
                  return (
                    <div className="p-2.5 bg-slate-950 border border-slate-700 rounded-lg shadow-xl font-mono text-xs space-y-1">
                      <div className="font-bold flex items-center justify-between gap-3 text-white">
                        <span>{item.band} ({item.priority})</span>
                        <span style={{ color: item.color }}>{item.count} items</span>
                      </div>
                      <div className="text-slate-400 text-[11px]">Threshold: {item.range} pts</div>
                      <div className="text-slate-400 text-[11px]">Share: {pct}% of total</div>
                    </div>
                  );
                }
                return null;
              }}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {data.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Legend & Proportions */}
      <div className="grid grid-cols-4 gap-2 pt-2 border-t border-slate-800/80 text-[11px] font-mono text-center">
        {data.map(item => (
          <div key={item.band} className="p-1.5 rounded bg-slate-950/60 border border-slate-800/60">
            <div className="text-slate-400 text-[10px]">{item.priority}</div>
            <div className="font-bold" style={{ color: item.color }}>
              {item.count} ({Math.round((item.count / total) * 100)}%)
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
