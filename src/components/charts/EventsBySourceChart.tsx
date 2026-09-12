import React from 'react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import { SourceDistributionPoint } from '../../types';

interface EventsBySourceChartProps {
  data: SourceDistributionPoint[];
  height?: number;
}

export const EventsBySourceChart: React.FC<EventsBySourceChartProps> = ({
  data,
  height = 280
}) => {
  return (
    <div className="w-full h-full min-h-[260px]" id="chart-events-by-source">
      <ResponsiveContainer width="100%" height={height}>
        <BarChart data={data} margin={{ top: 10, right: 10, left: -10, bottom: 20 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="source"
            stroke="#64748b"
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            axisLine={{ stroke: '#334155' }}
            tickLine={{ stroke: '#334155' }}
            angle={-10}
            textAnchor="end"
          />
          <YAxis
            stroke="#64748b"
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            axisLine={{ stroke: '#334155' }}
            tickLine={{ stroke: '#334155' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#0f172a',
              borderColor: '#334155',
              borderRadius: '8px',
              fontSize: '12px',
              color: '#f8fafc'
            }}
          />
          <Legend
            verticalAlign="top"
            align="right"
            iconType="circle"
            wrapperStyle={{ paddingBottom: '12px', fontSize: '11px' }}
          />
          <Bar
            name="Total Events"
            dataKey="count"
            fill="#38bdf8"
            radius={[4, 4, 0, 0]}
            maxBarSize={45}
          />
          <Bar
            name="Active Threats"
            dataKey="threats"
            fill="#f43f5e"
            radius={[4, 4, 0, 0]}
            maxBarSize={45}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
