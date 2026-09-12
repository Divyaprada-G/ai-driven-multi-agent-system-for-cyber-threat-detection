import React from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import { AgentActivityPoint } from '../../types';

interface AgentActivityChartProps {
  data: AgentActivityPoint[];
  height?: number;
}

export const AgentActivityChart: React.FC<AgentActivityChartProps> = ({
  data,
  height = 280
}) => {
  return (
    <div className="w-full h-full min-h-[260px]" id="chart-agent-activity">
      <ResponsiveContainer width="100%" height={height}>
        <LineChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
          <XAxis
            dataKey="time"
            stroke="#64748b"
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            axisLine={{ stroke: '#334155' }}
            tickLine={{ stroke: '#334155' }}
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
          <Line
            type="monotone"
            name="Network Agent"
            dataKey="networkAgent"
            stroke="#06b6d4"
            strokeWidth={2}
            dot={{ r: 3, fill: '#06b6d4' }}
            activeDot={{ r: 5 }}
          />
          <Line
            type="monotone"
            name="System Agent"
            dataKey="systemAgent"
            stroke="#10b981"
            strokeWidth={2}
            dot={{ r: 3, fill: '#10b981' }}
            activeDot={{ r: 5 }}
          />
          <Line
            type="monotone"
            name="Application Agent"
            dataKey="applicationAgent"
            stroke="#a855f7"
            strokeWidth={2}
            dot={{ r: 3, fill: '#a855f7' }}
            activeDot={{ r: 5 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};
