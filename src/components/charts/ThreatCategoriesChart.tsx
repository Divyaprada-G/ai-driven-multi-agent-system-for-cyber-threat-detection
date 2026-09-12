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
import { ThreatCategoryPoint } from '../../types';

interface ThreatCategoriesChartProps {
  data: ThreatCategoryPoint[];
  height?: number;
}

export const ThreatCategoriesChart: React.FC<ThreatCategoriesChartProps> = ({
  data,
  height = 280
}) => {
  return (
    <div className="w-full h-full min-h-[260px]" id="chart-threat-categories">
      <ResponsiveContainer width="100%" height={height}>
        <BarChart
          layout="vertical"
          data={data}
          margin={{ top: 10, right: 20, left: 30, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
          <XAxis
            type="number"
            stroke="#64748b"
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            axisLine={{ stroke: '#334155' }}
            tickLine={{ stroke: '#334155' }}
          />
          <YAxis
            dataKey="category"
            type="category"
            stroke="#64748b"
            tick={{ fill: '#94a3b8', fontSize: 11 }}
            axisLine={{ stroke: '#334155' }}
            tickLine={{ stroke: '#334155' }}
            width={120}
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
            name="Detected Incidents"
            dataKey="count"
            fill="#f97316"
            radius={[0, 4, 4, 0]}
            maxBarSize={22}
          />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};
