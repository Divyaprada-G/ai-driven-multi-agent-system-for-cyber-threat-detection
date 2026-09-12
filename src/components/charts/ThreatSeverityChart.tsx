import React from 'react';
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import { SeverityDistributionPoint } from '../../types';

interface ThreatSeverityChartProps {
  data: SeverityDistributionPoint[];
  height?: number;
}

export const ThreatSeverityChart: React.FC<ThreatSeverityChartProps> = ({
  data,
  height = 280
}) => {
  const total = data.reduce((acc, curr) => acc + curr.count, 0);

  return (
    <div className="w-full h-full min-h-[260px] flex flex-col items-center justify-center relative" id="chart-threat-severity">
      <ResponsiveContainer width="100%" height={height}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={65}
            outerRadius={95}
            paddingAngle={4}
            dataKey="count"
            nameKey="severity"
          >
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={entry.color} stroke="#0f172a" strokeWidth={2} />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#0f172a',
              borderColor: '#334155',
              borderRadius: '8px',
              fontSize: '12px',
              color: '#f8fafc'
            }}
            formatter={(val: number) => [`${val} (${((val / total) * 100).toFixed(1)}%)`, 'Events']}
          />
          <Legend
            verticalAlign="bottom"
            align="center"
            iconType="circle"
            wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }}
          />
        </PieChart>
      </ResponsiveContainer>

      {/* Center Label */}
      <div className="absolute top-[42%] left-1/2 -translate-x-1/2 -translate-y-1/2 text-center pointer-events-none">
        <span className="text-[10px] uppercase font-mono tracking-widest text-slate-400 block">
          Flagged
        </span>
        <span className="text-xl font-bold font-mono text-white">
          {total.toLocaleString()}
        </span>
      </div>
    </div>
  );
};
