import React from 'react';
import { CorrelatedEvent } from '../../types/correlation';
import { Network, Server, Globe, ShieldAlert, Cpu, ArrowDown, Clock, Flame, CheckCircle2 } from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';

interface CorrelationTimelineProps {
  correlatedEvent: CorrelatedEvent;
  onEscalate?: () => void;
}

export const CorrelationTimeline: React.FC<CorrelationTimelineProps> = ({ correlatedEvent, onEscalate }) => {
  const sequence = correlatedEvent.sequence || [];

  const getAgentTheme = (agentId: string) => {
    switch (agentId) {
      case 'NETWORK_AGENT':
        return {
          color: 'text-cyan-400',
          border: 'border-cyan-500/40',
          bg: 'bg-cyan-950/30',
          iconBg: 'bg-cyan-950 text-cyan-400 border-cyan-800',
          icon: Network,
          label: 'NETWORK AGENT'
        };
      case 'SYSTEM_AGENT':
        return {
          color: 'text-emerald-400',
          border: 'border-emerald-500/40',
          bg: 'bg-emerald-950/30',
          iconBg: 'bg-emerald-950 text-emerald-400 border-emerald-800',
          icon: Cpu,
          label: 'SYSTEM AGENT'
        };
      case 'APPLICATION_AGENT':
        return {
          color: 'text-purple-400',
          border: 'border-purple-500/40',
          bg: 'bg-purple-950/30',
          iconBg: 'bg-purple-950 text-purple-400 border-purple-800',
          icon: Globe,
          label: 'APPLICATION AGENT'
        };
      default:
        return {
          color: 'text-slate-300',
          border: 'border-slate-700',
          bg: 'bg-slate-900',
          iconBg: 'bg-slate-800 text-slate-300 border-slate-700',
          icon: ShieldAlert,
          label: 'SECURITY AGENT'
        };
    }
  };

  return (
    <div className="p-4 sm:p-5 bg-slate-950 border border-slate-800 rounded-xl space-y-4" id="correlation-timeline-container">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div>
          <h4 className="text-xs font-mono font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            Chronological Incident Timeline Reconstruction
          </h4>
          <p className="text-[11px] text-slate-400 mt-0.5">
            Temporal progression of observed multi-agent telemetry events.
          </p>
        </div>
        <div className="text-[11px] font-mono text-slate-400 bg-slate-900 px-2.5 py-1 rounded border border-slate-800">
          Span: {correlatedEvent.duration} • {sequence.length} Chronological Stages
        </div>
      </div>

      <div className="max-w-2xl mx-auto py-2 space-y-3">
        {sequence.map((step, idx) => {
          const theme = getAgentTheme(step.agentId);
          const Icon = theme.icon;

          return (
            <React.Fragment key={`${step.findingId}-${idx}`}>
              <div className={`w-full p-3.5 rounded-xl border ${theme.border} ${theme.bg} shadow-md flex items-start justify-between gap-3 transition-all`}>
                <div className="flex items-start gap-3">
                  <div className={`p-2 rounded-lg border ${theme.iconBg} shrink-0 mt-0.5`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="space-y-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`text-[11px] font-mono font-bold tracking-wider ${theme.color}`}>
                        STAGE {step.step}: {theme.label}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500 bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">
                        {step.timestamp.replace('T', ' ').substring(0, 19)}
                      </span>
                    </div>

                    <div className="text-xs font-semibold text-white">
                      {step.description}
                    </div>

                    <div className="flex flex-wrap items-center gap-3 text-[10px] font-mono text-slate-400 pt-0.5">
                      {step.sourceIp && <span>Src IP: <strong className="text-slate-300">{step.sourceIp}</strong></span>}
                      {step.host && <span>Host: <strong className="text-slate-300">{step.host}</strong></span>}
                      {step.user && <span>User: <strong className="text-slate-300">{step.user}</strong></span>}
                    </div>
                  </div>
                </div>

                <div className="shrink-0">
                  <SeverityBadge severity={step.severity} />
                </div>
              </div>

              {idx < sequence.length - 1 && (
                <div className="flex justify-center py-0.5">
                  <ArrowDown className="w-4 h-4 text-slate-600 animate-bounce" />
                </div>
              )}
            </React.Fragment>
          );
        })}

        {/* Synthesis Arrow */}
        <div className="flex justify-center py-1">
          <ArrowDown className="w-5 h-5 text-rose-500" />
        </div>

        {/* Correlated Activity Banner */}
        <div className="w-full p-4 bg-rose-950/40 border-2 border-rose-600 rounded-xl flex flex-col sm:flex-row sm:items-center justify-between gap-3 shadow-xl shadow-rose-950/50">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-lg bg-rose-900/60 border border-rose-600 text-rose-300 shrink-0">
              <Flame className="w-5 h-5 animate-pulse" />
            </div>
            <div>
              <div className="text-[11px] font-mono text-rose-300 font-bold uppercase tracking-wider flex items-center gap-2">
                SYNTHESIZED CORRELATED ACTIVITY
                <span className="px-2 py-0.5 rounded bg-rose-900/80 text-[10px] text-white font-mono">
                  CONFIDENCE: {Math.round((correlatedEvent.correlationConfidence || 0) * 100)}%
                </span>
              </div>
              <div className="text-sm font-bold text-white mt-0.5">
                {correlatedEvent.title}
              </div>
              <div className="text-xs text-rose-200/80 font-mono mt-0.5">
                Target Entities: {[...correlatedEvent.hosts, ...correlatedEvent.destinationIps].join(', ') || 'Internal DMZ Infrastructure'} • Status: {correlatedEvent.status}
              </div>
            </div>
          </div>

          {onEscalate && correlatedEvent.status !== 'ESCALATED' && (
            <button
              id="btn-timeline-escalate"
              onClick={onEscalate}
              className="px-3.5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-mono font-bold transition-colors shadow-lg shadow-rose-600/30 shrink-0 self-start sm:self-auto"
            >
              Escalate to Incident
            </button>
          )}

          {correlatedEvent.status === 'ESCALATED' && (
            <div className="flex items-center gap-1.5 text-xs font-mono text-emerald-400 bg-emerald-950/60 px-3 py-1.5 rounded-lg border border-emerald-800 shrink-0">
              <CheckCircle2 className="w-4 h-4" />
              <span>Escalated to P0 Incident</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
