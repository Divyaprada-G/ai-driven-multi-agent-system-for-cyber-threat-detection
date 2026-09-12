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
import { ThreatClass, ThreatDetectionResult } from '../../types/threatDetection';

interface ThreatCategoriesChartProps {
  detections: ThreatDetectionResult[];
  height?: number;
}

const THREAT_CLASS_COLORS: Record<ThreatClass, string> = {
  BENIGN: '#10b981', // emerald
  SUSPICIOUS: '#f59e0b', // amber
  NETWORK_THREAT: '#06b6d4', // cyan
  AUTHENTICATION_THREAT: '#3b82f6', // blue
  PRIVILEGE_ESCALATION: '#ef4444', // red
  WEB_THREAT: '#8b5cf6', // purple
  API_THREAT: '#ec4899', // pink
  MULTI_STAGE_THREAT: '#f43f5e', // rose
  ANOMALY: '#eab308', // yellow
  UNKNOWN: '#64748b' // slate
};

const THREAT_CLASS_LABELS: Record<ThreatClass, string> = {
  BENIGN: 'Benign',
  SUSPICIOUS: 'Suspicious',
  NETWORK_THREAT: 'Network Threat',
  AUTHENTICATION_THREAT: 'Auth Threat',
  PRIVILEGE_ESCALATION: 'Priv Escalation',
  WEB_THREAT: 'Web Threat',
  API_THREAT: 'API Threat',
  MULTI_STAGE_THREAT: 'Multi-Stage',
  ANOMALY: 'Anomaly',
  UNKNOWN: 'Unknown'
};

export const ThreatCategoriesChart: React.FC<ThreatCategoriesChartProps> = ({
  detections,
  height = 240
}) => {
  // Aggregate counts for all 10 threat classes
  const counts: Record<ThreatClass, number> = {
    BENIGN: 0,
    SUSPICIOUS: 0,
    NETWORK_THREAT: 0,
    AUTHENTICATION_THREAT: 0,
    PRIVILEGE_ESCALATION: 0,
    WEB_THREAT: 0,
    API_THREAT: 0,
    MULTI_STAGE_THREAT: 0,
    ANOMALY: 0,
    UNKNOWN: 0
  };

  for (const det of detections) {
    if (counts[det.classification] !== undefined) {
      counts[det.classification]++;
    } else {
      counts.UNKNOWN++;
    }
  }

  const chartData = (Object.keys(counts) as ThreatClass[]).map(cls => ({
    classification: cls,
    name: THREAT_CLASS_LABELS[cls],
    count: counts[cls],
    color: THREAT_CLASS_COLORS[cls]
  }));

  const totalDetections = detections.length;

  return (
    <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-2">
      <div className="flex items-center justify-between">
        <div>
          <h4 className="text-sm font-bold text-white font-mono">
            Threat Classification Distribution
          </h4>
          <p className="text-[11px] text-slate-400">
            Categorized across 10 academic threat & benign classes ({totalDetections} total evaluated).
          </p>
        </div>
        <span className="text-[10px] font-mono text-cyan-400">
          Distribution Metric
        </span>
      </div>

      <div style={{ width: '100%', height }}>
        <ResponsiveContainer>
          <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
            <XAxis
              dataKey="name"
              stroke="#64748b"
              fontSize={10}
              tickLine={false}
              interval={0}
              angle={-30}
              textAnchor="end"
            />
            <YAxis
              stroke="#64748b"
              fontSize={10}
              allowDecimals={false}
              tickLine={false}
            />
            <Tooltip
              contentStyle={{
                backgroundColor: '#020617',
                borderColor: '#1e293b',
                borderRadius: '8px',
                fontSize: '11px',
                fontFamily: 'monospace'
              }}
              formatter={(value: any, name: any, item: any) => [
                `${value} (${totalDetections > 0 ? ((Number(value) / totalDetections) * 100).toFixed(1) : 0}%)`,
                item.payload.classification
              ]}
            />
            <Bar dataKey="count" radius={[4, 4, 0, 0]}>
              {chartData.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={entry.color} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};
