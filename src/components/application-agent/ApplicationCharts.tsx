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
import { ApplicationAgentAnalysis } from '../../types/application';
import { Activity, Globe, ShieldAlert, BarChart3, Radio, Server } from 'lucide-react';

interface Props {
  analysis: ApplicationAgentAnalysis;
}

export const ApplicationCharts: React.FC<Props> = ({ analysis }) => {
  return (
    <div id="application-charts-section" className="space-y-4">
      {/* Row 1: Requests Over Time & HTTP Status Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Requests & Threat Volume Over Time */}
        <div className="lg:col-span-2 p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <Activity className="w-4 h-4 text-indigo-500" />
              <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
                Application Traffic & Threat Velocity Over Time
              </h3>
            </div>
            <span className="text-[11px] text-slate-500 dark:text-slate-400 font-mono">
              Bucket interval: 1m
            </span>
          </div>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={analysis.eventsOverTime}>
                <defs>
                  <linearGradient id="appReqGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#6366f1" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#6366f1" stopOpacity={0.0} />
                  </linearGradient>
                  <linearGradient id="appThreatGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.5} />
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} />
                <XAxis dataKey="time" stroke="#94a3b8" fontSize={11} />
                <YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                    color: '#f8fafc'
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px', paddingTop: '8px' }} />
                <Area
                  type="monotone"
                  dataKey="count"
                  name="Total HTTP/API Requests"
                  stroke="#6366f1"
                  fillOpacity={1}
                  fill="url(#appReqGrad)"
                  strokeWidth={2}
                />
                <Area
                  type="monotone"
                  dataKey="threats"
                  name="Detected Threats"
                  stroke="#f43f5e"
                  fillOpacity={1}
                  fill="url(#appThreatGrad)"
                  strokeWidth={2}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* HTTP Status Code Distribution */}
        <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <BarChart3 className="w-4 h-4 text-emerald-500" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
              HTTP Status Code Distribution
            </h3>
          </div>

          <div className="h-64 flex flex-col justify-center">
            {analysis.statusCodeDistribution.length === 0 ? (
              <div className="text-center text-xs text-slate-400">No status code data available</div>
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={analysis.statusCodeDistribution}
                    dataKey="count"
                    nameKey="statusCode"
                    cx="50%"
                    cy="45%"
                    innerRadius={45}
                    outerRadius={75}
                    paddingAngle={3}
                  >
                    {analysis.statusCodeDistribution.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#0f172a',
                      borderColor: '#334155',
                      borderRadius: '8px',
                      fontSize: '11px',
                      color: '#f8fafc'
                    }}
                  />
                  <Legend
                    verticalAlign="bottom"
                    layout="horizontal"
                    wrapperStyle={{ fontSize: '10px', paddingTop: '10px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Row 2: Top Endpoints & Top Source IPs */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Endpoints */}
        <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <Globe className="w-4 h-4 text-cyan-500" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
              Top Target Endpoints (Volume & Errors)
            </h3>
          </div>

          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analysis.topEndpoints} layout="vertical" margin={{ left: 15, right: 15 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} horizontal={false} />
                <XAxis type="number" stroke="#94a3b8" fontSize={10} />
                <YAxis dataKey="endpoint" type="category" stroke="#94a3b8" fontSize={10} width={110} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                    color: '#f8fafc'
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Bar dataKey="count" name="Total Requests" fill="#3b82f6" radius={[0, 4, 4, 0]} />
                <Bar dataKey="errors" name="HTTP Errors (4xx/5xx)" fill="#ef4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Top Source IPs */}
        <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <Server className="w-4 h-4 text-violet-500" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
              Top Client Source IPs (Volume & Suspicious)
            </h3>
          </div>

          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analysis.topSourceIps} layout="vertical" margin={{ left: 15, right: 15 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} horizontal={false} />
                <XAxis type="number" stroke="#94a3b8" fontSize={10} />
                <YAxis dataKey="sourceIp" type="category" stroke="#94a3b8" fontSize={10} width={95} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                    color: '#f8fafc'
                  }}
                />
                <Legend wrapperStyle={{ fontSize: '11px' }} />
                <Bar dataKey="count" name="Total Ingress" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
                <Bar dataKey="threats" name="Suspicious / Errors" fill="#f97316" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Row 3: HTTP Methods & Severity Distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* HTTP Methods */}
        <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <Radio className="w-4 h-4 text-blue-500" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
              HTTP Methods Distribution
            </h3>
          </div>

          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analysis.methodDistribution}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} vertical={false} />
                <XAxis dataKey="method" stroke="#94a3b8" fontSize={11} />
                <YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                    color: '#f8fafc'
                  }}
                />
                <Bar dataKey="count" name="Requests" radius={[4, 4, 0, 0]}>
                  {analysis.methodDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
          <div className="flex items-center gap-2 mb-4">
            <ShieldAlert className="w-4 h-4 text-rose-500" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
              Detections by Severity Tier
            </h3>
          </div>

          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={analysis.threatSeverityDistribution}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} vertical={false} />
                <XAxis dataKey="severity" stroke="#94a3b8" fontSize={11} />
                <YAxis stroke="#94a3b8" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#0f172a',
                    borderColor: '#334155',
                    borderRadius: '8px',
                    fontSize: '11px',
                    color: '#f8fafc'
                  }}
                />
                <Bar dataKey="count" name="Findings Count" radius={[4, 4, 0, 0]}>
                  {analysis.threatSeverityDistribution.map((entry, index) => (
                    <Cell key={`sev-cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};
