import React from 'react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import { NetworkAgentAnalysis } from '../../types';
import { Activity, Radio, BarChart3, PieChart as PieIcon, ShieldAlert } from 'lucide-react';

interface NetworkChartsProps {
  analysis: NetworkAgentAnalysis;
}

const PROTOCOL_COLORS = ['#06b6d4', '#3b82f6', '#10b981', '#f59e0b', '#a855f7'];
const SEVERITY_COLORS: Record<string, string> = {
  LOW: '#3b82f6',
  MEDIUM: '#f59e0b',
  HIGH: '#f97316',
  CRITICAL: '#ef4444'
};

export const NetworkCharts: React.FC<NetworkChartsProps> = ({ analysis }) => {
  const topSourcesData = analysis.topSourceIps.map(s => ({
    ip: s.ip.length > 14 ? s.ip.substring(0, 12) + '..' : s.ip,
    fullIp: s.ip,
    count: s.eventCount,
    risk: s.riskIndicator
  }));

  const topDestData = analysis.topDestinationIps.map(d => ({
    ip: d.ip.length > 14 ? d.ip.substring(0, 12) + '..' : d.ip,
    fullIp: d.ip,
    count: d.eventCount
  }));

  const portData = analysis.portDistribution.slice(0, 6).map(p => ({
    portLabel: `${p.port} (${p.service || 'Port'})`,
    count: p.count
  }));

  const protocolData = analysis.protocolDistribution;
  const severityData = analysis.severityDistribution.filter(s => s.count > 0);

  return (
    <div className="space-y-4" id="network-charts-section">
      {/* Row 1: Events Over Time + Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold text-white font-mono">
                Network Activity Timeline (Normal vs. Suspicious)
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-500">Flow Volume</span>
          </div>

          <div className="h-[230px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={analysis.eventsOverTime}
                margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="netNormalGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.35} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="netSuspGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
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
                    fontSize: '12px'
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                <Area
                  type="monotone"
                  dataKey="normal"
                  name="Normal Flow Events"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  fill="url(#netNormalGrad)"
                />
                <Area
                  type="monotone"
                  dataKey="suspicious"
                  name="Suspicious / Threat Findings"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fill="url(#netSuspGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Breakdown */}
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-bold text-white font-mono">Severity Distribution</h3>
            </div>
            <span className="text-[11px] font-mono text-slate-500">Findings</span>
          </div>

          <div className="h-[180px] w-full flex items-center justify-center">
            {severityData.length === 0 ? (
              <div className="text-xs font-mono text-slate-500">No active findings</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="count"
                    nameKey="severity"
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={75}
                    paddingAngle={3}
                  >
                    {severityData.map(entry => (
                      <Cell
                        key={entry.severity}
                        fill={SEVERITY_COLORS[entry.severity] || '#64748b'}
                      />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px'
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800 text-xs font-mono">
            {analysis.severityDistribution.map(s => (
              <div key={s.severity} className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: s.color }}
                  />
                  <span className="text-slate-400">{s.severity}</span>
                </div>
                <span className="text-slate-200 font-bold">{s.count}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 2: Top Source IPs, Top Destination IPs, Port Distribution, Protocol */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Top Source IPs */}
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-xs font-bold text-white font-mono flex items-center gap-1.5">
              <BarChart3 className="w-3.5 h-3.5 text-cyan-400" />
              Top Source IPs
            </h4>
            <span className="text-[10px] font-mono text-slate-500">by volume</span>
          </div>
          <div className="h-[160px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topSourcesData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="ip" stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 9 }} />
                <YAxis stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <Tooltip
                  formatter={(val, name, item) => [val, `IP: ${item.payload.fullIp}`]}
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                />
                <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Destination IPs */}
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-xs font-bold text-white font-mono flex items-center gap-1.5">
              <BarChart3 className="w-3.5 h-3.5 text-emerald-400" />
              Top Destination IPs
            </h4>
            <span className="text-[10px] font-mono text-slate-500">by targets</span>
          </div>
          <div className="h-[160px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topDestData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="ip" stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 9 }} />
                <YAxis stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 10 }} />
                <Tooltip
                  formatter={(val, name, item) => [val, `Target: ${item.payload.fullIp}`]}
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                />
                <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Destination Port Distribution */}
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-xs font-bold text-white font-mono flex items-center gap-1.5">
              <Radio className="w-3.5 h-3.5 text-amber-400" />
              Target Ports
            </h4>
            <span className="text-[10px] font-mono text-slate-500">common services</span>
          </div>
          <div className="h-[160px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                layout="vertical"
                data={portData}
                margin={{ top: 5, right: 10, left: 10, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" stroke="#64748b" tick={{ fill: '#94a3b8', fontSize: 9 }} />
                <YAxis
                  type="category"
                  dataKey="portLabel"
                  stroke="#64748b"
                  tick={{ fill: '#94a3b8', fontSize: 9 }}
                  width={65}
                />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                />
                <Bar dataKey="count" fill="#f59e0b" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Protocol Distribution */}
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <h4 className="text-xs font-bold text-white font-mono flex items-center gap-1.5">
              <PieIcon className="w-3.5 h-3.5 text-purple-400" />
              Protocols
            </h4>
            <span className="text-[10px] font-mono text-slate-500">L4/L7</span>
          </div>
          <div className="h-[120px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protocolData}
                  dataKey="count"
                  nameKey="protocol"
                  cx="50%"
                  cy="50%"
                  outerRadius={50}
                  innerRadius={25}
                  paddingAngle={2}
                >
                  {protocolData.map((entry, idx) => (
                    <Cell key={entry.protocol} fill={PROTOCOL_COLORS[idx % PROTOCOL_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '6px', fontSize: '11px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex flex-wrap gap-2 text-[10px] font-mono pt-2 border-t border-slate-800">
            {protocolData.map((p, i) => (
              <span key={p.protocol} className="text-slate-300">
                <span
                  className="inline-block w-2 h-2 rounded-full mr-1"
                  style={{ backgroundColor: PROTOCOL_COLORS[i % PROTOCOL_COLORS.length] }}
                />
                {p.protocol}: {p.count}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
