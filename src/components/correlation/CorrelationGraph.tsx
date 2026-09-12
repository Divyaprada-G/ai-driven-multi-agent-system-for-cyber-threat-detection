import React from 'react';
import { CorrelatedEvent } from '../../types/correlation';
import { Network, Server, Globe, ShieldAlert, Cpu, ArrowRight, Layers, Lock, User, HardDrive } from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';

interface CorrelationGraphProps {
  correlatedEvent: CorrelatedEvent;
}

export const CorrelationGraph: React.FC<CorrelationGraphProps> = ({ correlatedEvent }) => {
  const sequence = correlatedEvent.sequence || [];

  const getAgentColor = (agentId: string) => {
    switch (agentId) {
      case 'NETWORK_AGENT':
        return {
          border: 'border-cyan-500/50',
          bg: 'bg-cyan-950/40',
          badge: 'bg-cyan-950 text-cyan-400 border-cyan-800',
          text: 'text-cyan-400',
          icon: Network
        };
      case 'SYSTEM_AGENT':
        return {
          border: 'border-emerald-500/50',
          bg: 'bg-emerald-950/40',
          badge: 'bg-emerald-950 text-emerald-400 border-emerald-800',
          text: 'text-emerald-400',
          icon: Cpu
        };
      case 'APPLICATION_AGENT':
        return {
          border: 'border-purple-500/50',
          bg: 'bg-purple-950/40',
          badge: 'bg-purple-950 text-purple-400 border-purple-800',
          text: 'text-purple-400',
          icon: Globe
        };
      default:
        return {
          border: 'border-slate-700',
          bg: 'bg-slate-900',
          badge: 'bg-slate-800 text-slate-300 border-slate-700',
          text: 'text-slate-300',
          icon: ShieldAlert
        };
    }
  };

  const primaryIp = correlatedEvent.sourceIps[0] || 'Internal Origin';
  const primaryHost = correlatedEvent.hosts[0];
  const primaryUser = correlatedEvent.users[0];

  return (
    <div className="p-4 sm:p-5 bg-slate-950 border border-slate-800 rounded-xl space-y-4" id="correlation-graph-container">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-cyan-400" />
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200">
            Multi-Agent Correlation Topology Graph
          </h4>
        </div>
        <div className="flex items-center gap-2 text-[11px] font-mono">
          <span className="text-slate-400">Strength:</span>
          <span className={`px-2 py-0.5 rounded font-bold ${
            correlatedEvent.correlationStrength === 'HIGH'
              ? 'bg-rose-950 text-rose-300 border border-rose-800'
              : correlatedEvent.correlationStrength === 'MEDIUM'
              ? 'bg-amber-950 text-amber-300 border border-amber-800'
              : 'bg-slate-800 text-slate-300 border border-slate-700'
          }`}>
            {correlatedEvent.correlationStrength}
          </span>
          <span className="text-slate-500">|</span>
          <span className="text-slate-400">Confidence:</span>
          <span className="text-emerald-400 font-bold">{Math.round((correlatedEvent.correlationConfidence || 0) * 100)}%</span>
        </div>
      </div>

      {/* Responsive Graph Topology Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-stretch py-2">
        {/* Layer 1: Correlated Identity & Ingress Entities (Cols 1-3) */}
        <div className="lg:col-span-3 flex flex-col justify-center space-y-3">
          <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            Correlated Ingress / Host Entity
          </div>

          <div className="p-3.5 bg-slate-900 border border-slate-800 rounded-xl space-y-2.5 shadow-md">
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-white">
              <HardDrive className="w-4 h-4 text-cyan-400" />
              <span>Source IP: {primaryIp}</span>
            </div>

            {primaryHost && (
              <div className="flex items-center gap-2 text-xs font-mono text-slate-300 pt-1 border-t border-slate-800/80">
                <Server className="w-3.5 h-3.5 text-emerald-400" />
                <span>Host: {primaryHost}</span>
              </div>
            )}

            {primaryUser && (
              <div className="flex items-center gap-2 text-xs font-mono text-slate-300 pt-1 border-t border-slate-800/80">
                <User className="w-3.5 h-3.5 text-purple-400" />
                <span>User: {primaryUser}</span>
              </div>
            )}

            <div className="text-[10px] font-mono text-slate-500 pt-1">
              Temporal Span: {correlatedEvent.duration}
            </div>
          </div>
        </div>

        {/* Middle Connector Arrow (Desktop Only) */}
        <div className="hidden lg:flex lg:col-span-1 items-center justify-center">
          <div className="flex flex-col items-center">
            <div className="w-0.5 h-8 bg-slate-800" />
            <ArrowRight className="w-5 h-5 text-cyan-500 my-1 animate-pulse" />
            <div className="w-0.5 h-8 bg-slate-800" />
          </div>
        </div>

        {/* Layer 2: Participating Agent Nodes & Detections (Cols 5-8) */}
        <div className="lg:col-span-5 flex flex-col justify-center space-y-2.5">
          <div className="text-[10px] font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-purple-400" />
            Domain Agents & Security Findings ({sequence.length})
          </div>

          <div className="space-y-2">
            {sequence.map((step, idx) => {
              const styling = getAgentColor(step.agentId);
              const Icon = styling.icon;

              return (
                <div
                  key={`${step.findingId}-${idx}`}
                  className={`p-3 rounded-lg border ${styling.border} ${styling.bg} transition-all`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <div className={`p-1.5 rounded border ${styling.badge}`}>
                        <Icon className="w-3.5 h-3.5" />
                      </div>
                      <div>
                        <div className={`text-[10px] font-mono uppercase tracking-wider font-bold ${styling.text}`}>
                          Step {step.step}: {step.agentId.replace('_', ' ')}
                        </div>
                        <div className="text-xs font-semibold text-slate-200 line-clamp-1">
                          {step.description}
                        </div>
                      </div>
                    </div>
                    <SeverityBadge severity={step.severity} />
                  </div>
                  <div className="mt-1 flex items-center justify-between text-[10px] font-mono text-slate-400 pt-1 border-t border-slate-800/60">
                    <span>{step.timestamp.replace('T', ' ').substring(0, 19)}</span>
                    <span className="text-slate-500">ID: {step.findingId.substring(0, 16)}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Second Connector Arrow (Desktop Only) */}
        <div className="hidden lg:flex lg:col-span-1 items-center justify-center">
          <div className="flex flex-col items-center">
            <div className="w-0.5 h-8 bg-slate-800" />
            <ArrowRight className="w-5 h-5 text-rose-500 my-1 animate-pulse" />
            <div className="w-0.5 h-8 bg-slate-800" />
          </div>
        </div>

        {/* Layer 3: Synthesized Correlated Security Incident (Cols 10-12) */}
        <div className="lg:col-span-2 flex flex-col justify-center space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-wider text-rose-400 flex items-center gap-1.5 font-bold">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
            Correlated Activity
          </div>

          <div className="p-3.5 bg-rose-950/30 border-2 border-rose-600/70 rounded-xl space-y-2 shadow-lg shadow-rose-950/40">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded bg-rose-900/60 text-rose-300 border border-rose-700">
                <ShieldAlert className="w-4 h-4" />
              </div>
              <div className="text-[11px] font-mono font-bold text-rose-300 truncate">
                {correlatedEvent.id}
              </div>
            </div>

            <div className="text-xs font-bold text-white line-clamp-2">
              {correlatedEvent.title}
            </div>

            <div className="pt-2 border-t border-rose-900/60 flex items-center justify-between text-[11px] font-mono">
              <span className="text-slate-400">Severity:</span>
              <SeverityBadge severity={correlatedEvent.severity} />
            </div>

            <div className="flex items-center justify-between text-[11px] font-mono">
              <span className="text-slate-400">Status:</span>
              <span className="text-amber-400 font-bold">{correlatedEvent.status}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
