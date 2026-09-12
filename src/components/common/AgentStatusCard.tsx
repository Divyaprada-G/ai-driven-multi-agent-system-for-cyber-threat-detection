import React from 'react';
import { AgentStatusInfo } from '../../types';
import { StatusBadge } from './StatusBadge';
import { Shield, Activity, AlertTriangle, Clock, Cpu, ArrowRight } from 'lucide-react';

interface AgentStatusCardProps {
  agent: AgentStatusInfo;
  onViewDetails?: (agentId: string) => void;
  onToggleStatus?: (agentId: string) => void;
}

export const AgentStatusCard: React.FC<AgentStatusCardProps> = ({
  agent,
  onViewDetails,
  onToggleStatus
}) => {
  const isNetwork = agent.agentId === 'NETWORK_AGENT';
  const isSystem = agent.agentId === 'SYSTEM_AGENT';
  const isApp = agent.agentId === 'APPLICATION_AGENT';

  const accentBorder = isNetwork
    ? 'border-cyan-500/40 hover:border-cyan-400/70'
    : isSystem
    ? 'border-emerald-500/40 hover:border-emerald-400/70'
    : 'border-purple-500/40 hover:border-purple-400/70';

  const accentBadge = isNetwork
    ? 'text-cyan-400 bg-cyan-950/40 border-cyan-800/50'
    : isSystem
    ? 'text-emerald-400 bg-emerald-950/40 border-emerald-800/50'
    : 'text-purple-400 bg-purple-950/40 border-purple-800/50';

  return (
    <div
      id={`agent-card-${agent.agentId.toLowerCase().replace(/_/g, '-')}`}
      className={`relative p-5 rounded-xl bg-slate-900/80 border ${accentBorder} backdrop-blur-md transition-all duration-200 flex flex-col justify-between`}
    >
      <div>
        {/* Header */}
        <div className="flex items-center justify-between gap-3 mb-3">
          <div className="flex items-center gap-2.5">
            <div className={`p-2 rounded-lg border ${accentBadge}`}>
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-tight flex items-center gap-2">
                {agent.name}
              </h3>
              <p className="text-xs text-slate-400 font-mono">ID: {agent.agentId}</p>
            </div>
          </div>
          <StatusBadge status={agent.status} type="agent" />
        </div>

        <p className="text-xs text-slate-300 leading-relaxed mb-4 line-clamp-2">
          {agent.description}
        </p>

        {/* Metrics Grid */}
        <div className="grid grid-cols-2 gap-3 py-3 border-y border-slate-800/80 mb-4 bg-slate-950/40 p-3 rounded-lg">
          <div>
            <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
              <Activity className="w-3.5 h-3.5 text-slate-500" />
              <span>Events Processed</span>
            </div>
            <div className="text-lg font-bold font-mono text-white mt-0.5">
              {agent.eventsProcessed.toLocaleString()}
            </div>
          </div>

          <div>
            <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-500" />
              <span>Threats Detected</span>
            </div>
            <div className="text-lg font-bold font-mono text-amber-400 mt-0.5">
              {agent.threatsDetected.toLocaleString()}
            </div>
          </div>

          <div>
            <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
              <Clock className="w-3.5 h-3.5 text-slate-500" />
              <span>Last Activity</span>
            </div>
            <div className="text-xs font-semibold text-slate-200 mt-1">
              {agent.lastActivity}
            </div>
          </div>

          <div>
            <div className="flex items-center gap-1.5 text-xs text-slate-400 font-mono">
              <Shield className="w-3.5 h-3.5 text-emerald-500" />
              <span>Confidence</span>
            </div>
            <div className="text-xs font-bold text-emerald-400 font-mono mt-1">
              {agent.detectionConfidence}%
            </div>
          </div>
        </div>

        {/* Confidence progress bar */}
        <div className="mb-4">
          <div className="flex justify-between items-center text-[11px] text-slate-400 font-mono mb-1.5">
            <span>Model Confidence Threshold</span>
            <span className="text-slate-200">{agent.detectionConfidence}%</span>
          </div>
          <div className="w-full h-1.5 bg-slate-800 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                isNetwork ? 'bg-cyan-400' : isSystem ? 'bg-emerald-400' : 'bg-purple-400'
              }`}
              style={{ width: `${agent.detectionConfidence}%` }}
            />
          </div>
        </div>
      </div>

      {/* Action Footer */}
      <div className="flex items-center justify-between gap-2 pt-2 border-t border-slate-800/60">
        <button
          id={`btn-toggle-agent-${agent.agentId.toLowerCase()}`}
          onClick={() => onToggleStatus && onToggleStatus(agent.agentId)}
          className="text-xs font-mono px-2.5 py-1.5 rounded-lg border border-slate-700 bg-slate-800/60 hover:bg-slate-800 text-slate-300 hover:text-white transition-colors"
        >
          {agent.status === 'READY' ? 'Simulate Pause' : 'Activate Agent'}
        </button>

        {onViewDetails && (
          <button
            id={`btn-view-agent-${agent.agentId.toLowerCase()}`}
            onClick={() => onViewDetails(agent.agentId)}
            className="inline-flex items-center gap-1.5 text-xs font-medium text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            <span>View Agent Telemetry</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        )}
      </div>
    </div>
  );
};
