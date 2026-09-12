/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Multi-Agent Activity & Comparative Analytics Panel
 *
 * Implements:
 * - Section 11: Specialized Agent Metrics (Network, System, Application)
 * - Section 12: Agent comparison visualization with protocol volume clarification note
 */

import React from 'react';
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend
} from 'recharts';
import {
  Network,
  Server,
  Globe,
  Activity,
  ShieldCheck,
  AlertTriangle,
  Info,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import { NavPageId } from '../../types';

interface AgentDetailInfo {
  id: string;
  name: string;
  eventCount: number;
  findingCount: number;
  threatContribution: number;
  correlatedEvents: number;
  lastActivity: string;
  status: string;
  domain: string;
}

interface MultiAgentActivityPanelProps {
  agents: AgentDetailInfo[];
  comparativeNote: string;
  onNavigate?: (page: NavPageId) => void;
}

export const MultiAgentActivityPanel: React.FC<MultiAgentActivityPanelProps> = ({
  agents,
  comparativeNote,
  onNavigate
}) => {
  const getAgentIcon = (id: string) => {
    switch (id) {
      case 'NETWORK_AGENT':
        return <Network className="w-5 h-5 text-cyan-400" />;
      case 'SYSTEM_AGENT':
        return <Server className="w-5 h-5 text-indigo-400" />;
      case 'APPLICATION_AGENT':
      default:
        return <Globe className="w-5 h-5 text-amber-400" />;
    }
  };

  const getAgentPage = (id: string): NavPageId => {
    switch (id) {
      case 'NETWORK_AGENT':
        return 'network-agent';
      case 'SYSTEM_AGENT':
        return 'system-agent';
      case 'APPLICATION_AGENT':
      default:
        return 'application-agent';
    }
  };

  // Comparative data for chart
  const chartData = agents.map(a => ({
    name: a.name.replace(' Security Agent', ''),
    'Findings Flagged': a.findingCount,
    'Threats Contributed': a.threatContribution,
    'Correlated Clusters': a.correlatedEvents
  }));

  return (
    <div className="space-y-4">
      {/* 3 Specialized Agent Activity Cards (Section 11) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {agents.map(agent => (
          <div
            key={agent.id}
            className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow space-y-3 flex flex-col justify-between hover:border-slate-700 transition-all"
          >
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-slate-950 border border-slate-800">
                    {getAgentIcon(agent.id)}
                  </div>
                  <div>
                    <h4 className="text-sm font-bold font-mono text-white">
                      {agent.name}
                    </h4>
                    <span className="text-[10px] font-mono text-slate-500 block">
                      {agent.domain}
                    </span>
                  </div>
                </div>

                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                  {agent.status}
                </span>
              </div>

              {/* Metrics Grid */}
              <div className="grid grid-cols-2 gap-2 mt-4 text-xs font-mono">
                <div className="p-2 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-[10px] text-slate-500 uppercase block">Events Monitored</span>
                  <span className="text-sm font-bold text-white">
                    {agent.eventCount.toLocaleString()}
                  </span>
                </div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-[10px] text-slate-500 uppercase block">Findings Flagged</span>
                  <span className="text-sm font-bold text-cyan-400">
                    {agent.findingCount.toLocaleString()}
                  </span>
                </div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-[10px] text-slate-500 uppercase block">Threats Contributed</span>
                  <span className="text-sm font-bold text-rose-400">
                    {agent.threatContribution}
                  </span>
                </div>
                <div className="p-2 rounded bg-slate-950 border border-slate-800/80">
                  <span className="text-[10px] text-slate-500 uppercase block">Correlated Clusters</span>
                  <span className="text-sm font-bold text-indigo-300">
                    {agent.correlatedEvents}
                  </span>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
              <span className="text-[10px] text-slate-500">
                Last Heartbeat: <strong className="text-slate-300">{agent.lastActivity}</strong>
              </span>
              <button
                onClick={() => onNavigate && onNavigate(getAgentPage(agent.id))}
                className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-bold transition-colors inline-flex items-center gap-1"
              >
                <span>Console</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            </div>
          </div>
        ))}
      </div>

      {/* Comparative Visualization & Academic Clarification Note (Section 12) */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow space-y-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-indigo-400" />
            <h3 className="text-sm font-bold font-mono text-white">
              Multi-Agent Comparative Contribution
            </h3>
          </div>
          <span className="text-[10px] font-mono text-slate-500">
            Across Suspicious Findings, Confirmed Threats & Correlation Clusters
          </span>
        </div>

        <div className="h-60 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} margin={{ top: 10, right: 30, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="name" stroke="#64748b" tick={{ fontSize: 11, fill: '#94a3b8' }} />
              <YAxis stroke="#64748b" tick={{ fontSize: 10, fill: '#64748b' }} />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0f172a',
                  borderColor: '#334155',
                  borderRadius: '8px',
                  fontSize: '11px',
                  fontFamily: 'monospace'
                }}
              />
              <Legend wrapperStyle={{ fontSize: '11px', fontFamily: 'monospace' }} />
              <Bar dataKey="Findings Flagged" fill="#38bdf8" radius={[4, 4, 0, 0]} />
              <Bar dataKey="Threats Contributed" fill="#f43f5e" radius={[4, 4, 0, 0]} />
              <Bar dataKey="Correlated Clusters" fill="#818cf8" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Mandatory Academic Clarification Note (Section 12) */}
        <div className="p-3 bg-slate-950 border border-slate-800/80 rounded-lg flex items-start gap-2.5 text-xs font-mono text-slate-400">
          <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
          <p className="leading-relaxed">
            <strong className="text-white">Academic Comparative Note: </strong>
            {comparativeNote}
          </p>
        </div>
      </div>
    </div>
  );
};
