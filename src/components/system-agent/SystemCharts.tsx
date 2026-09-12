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
import { SystemAgentAnalysis } from '../../types';
import { ShieldAlert, BarChart3, Key, Server, UserCheck, Shield } from 'lucide-react';

interface SystemChartsProps {
  analysis: SystemAgentAnalysis;
}

const SEVERITY_COLORS: Record<string, string> = {
  LOW: '#3b82f6',
  MEDIUM: '#f59e0b',
  HIGH: '#f97316',
  CRITICAL: '#ef4444'
};

export const SystemCharts: React.FC<SystemChartsProps> = ({ analysis }) => {
  const authRatio = analysis.authRatioDistribution.filter(d => d.value > 0);
  const totalAuth = analysis.authEventsCount;

  return (
    <div className="space-y-4" id="system-charts-section">
      {/* Top Row: Auth Over Time & Auth Success vs Failure Ratio */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Authentication Events Over Time */}
        <div className="lg:col-span-2 p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Key className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white font-mono">
                Authentication Events Over Time
              </h3>
            </div>
            <span className="text-[11px] font-mono text-slate-400">
              Successful vs Failed Login Chronology
            </span>
          </div>

          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart
                data={analysis.authOverTime}
                margin={{ top: 10, right: 20, left: -15, bottom: 0 }}
              >
                <defs>
                  <linearGradient id="colorSuccess" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#10b981" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#10b981" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="colorFailed" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.6} />
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 11, fill: '#94a3b8' }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 11, fill: '#94a3b8' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px'
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
                <Area
                  type="monotone"
                  dataKey="successful"
                  name="Successful Logins"
                  stroke="#10b981"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorSuccess)"
                />
                <Area
                  type="monotone"
                  dataKey="failed"
                  name="Failed Logins"
                  stroke="#ef4444"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#colorFailed)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Successful vs Failed Logins Ratio */}
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center gap-2 mb-3">
              <UserCheck className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white font-mono">
                Logon Success Ratio
              </h3>
            </div>
            <p className="text-xs text-slate-400">
              Authentication outcome balance across all evaluated user accounts.
            </p>
          </div>

          <div className="h-44 w-full relative flex items-center justify-center">
            {totalAuth === 0 ? (
              <div className="text-xs text-slate-500 font-mono">No authentication telemetry</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={authRatio}
                    cx="50%"
                    cy="50%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {authRatio.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
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

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800 text-center">
            <div className="bg-slate-950/60 p-2 rounded-lg border border-slate-800/80">
              <span className="text-[10px] font-mono text-emerald-400 uppercase font-semibold block">
                Success
              </span>
              <span className="text-sm font-bold text-white">
                {analysis.successfulLoginsCount}
              </span>
            </div>
            <div className="bg-slate-950/60 p-2 rounded-lg border border-slate-800/80">
              <span className="text-[10px] font-mono text-rose-400 uppercase font-semibold block">
                Failed
              </span>
              <span className="text-sm font-bold text-white">
                {analysis.failedLoginsCount}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Middle Row: Top Users Auth, Top Hosts Events, Failed Sources */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Top Users by Authentication Attempts */}
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white font-mono">
                Top Users (Auth Attempts)
              </h3>
            </div>
          </div>

          <div className="h-48 w-full">
            {analysis.topUsersAuth.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
                No user authentication data
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={analysis.topUsersAuth}
                  margin={{ top: 10, right: 10, left: -20, bottom: 20 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="username"
                    stroke="#64748b"
                    tick={{ fontSize: 10, fill: '#94a3b8' }}
                    angle={-25}
                    textAnchor="end"
                  />
                  <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px'
                    }}
                  />
                  <Bar dataKey="attempts" name="Total Attempts" fill="#06b6d4" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="failed" name="Failed Attempts" fill="#ef4444" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Top Hosts by Events & Threats */}
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <Server className="w-4 h-4 text-indigo-400" />
              <h3 className="text-sm font-semibold text-white font-mono">
                Top Hosts by Event Volume
              </h3>
            </div>
          </div>

          <div className="h-48 w-full">
            {analysis.topHostsEvents.length === 0 ? (
              <div className="h-full flex items-center justify-center text-xs text-slate-500 font-mono">
                No host telemetry available
              </div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={analysis.topHostsEvents}
                  margin={{ top: 10, right: 10, left: -20, bottom: 20 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="host"
                    stroke="#64748b"
                    tick={{ fontSize: 10, fill: '#94a3b8' }}
                    angle={-25}
                    textAnchor="end"
                  />
                  <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '12px'
                    }}
                  />
                  <Bar dataKey="count" name="Total Events" fill="#6366f1" radius={[4, 4, 0, 0]} />
                  <Bar dataKey="threats" name="Threats Flagged" fill="#f97316" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Failed Login Sources & Severity Distribution */}
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl flex flex-col justify-between">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-rose-400" />
              <h3 className="text-sm font-semibold text-white font-mono">
                System Severity Distribution
              </h3>
            </div>
          </div>

          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={analysis.severityDistribution}
                margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="severity" stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: '#94a3b8' }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '12px'
                  }}
                />
                <Bar dataKey="count" name="Findings" radius={[4, 4, 0, 0]}>
                  {analysis.severityDistribution.map(entry => (
                    <Cell key={`cell-${entry.severity}`} fill={SEVERITY_COLORS[entry.severity] || '#64748b'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-400">
            <span>Critical: {analysis.severityDistribution.find(s => s.severity === 'CRITICAL')?.count || 0}</span>
            <span>High: {analysis.severityDistribution.find(s => s.severity === 'HIGH')?.count || 0}</span>
            <span>Med: {analysis.severityDistribution.find(s => s.severity === 'MEDIUM')?.count || 0}</span>
          </div>
        </div>
      </div>
    </div>
  );
};
