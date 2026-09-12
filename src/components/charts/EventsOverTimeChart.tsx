import React from 'react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import { TimeSeriesPoint } from '../../types';

interface EventsOverTimeChartProps {
  data: TimeSeriesPoint[];
  height?: number;
}

export const EventsOverTimeChart: React.FC<EventsOverTimeChartProps> = ({
  data,
  height = 280
}) => {
  return (
    <div className="w-full h-full min-h-[260px]" id="chart-events-over-time">
      <ResponsiveContainer width="100%" height={height}>
        <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="networkGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="systemGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
            </linearGradient>
            <linearGradient id="appGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#a855f7" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#a855f7" stopOpacity={0.0} />
            </linearGradient>
          </defs>
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
              color: '#f8fafc',
              boxShadow: '0 4px 12px rgba(0,0,0,0.5)'
            }}
          />
          <Legend
            verticalAlign="top"
            align="right"
            iconType="circle"
            wrapperStyle={{ paddingBottom: '12px', fontSize: '12px', color: '#94a3b8' }}
          />
          <Area
            type="monotone"
            name="Network"
            dataKey="networkEvents"
            stroke="#06b6d4"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#networkGradient)"
          />
          <Area
            type="monotone"
            name="System"
            dataKey="systemEvents"
            stroke="#10b981"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#systemGradient)"
          />
          <Area
            type="monotone"
            name="Application"
            dataKey="applicationEvents"
            stroke="#a855f7"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#appGradient)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};
