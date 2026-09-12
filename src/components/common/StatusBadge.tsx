import React from 'react';

interface StatusBadgeProps {
  status: string;
  type?: 'agent' | 'incident' | 'alert' | 'general';
}

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, type = 'general' }) => {
  const s = status.toUpperCase();

  let style = 'bg-slate-800 text-slate-300 border-slate-700';
  let dot = 'bg-slate-400';

  if (s === 'READY' || s === 'RESOLVED' || s === 'COMPLETED' || s === 'ONLINE') {
    style = 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60';
    dot = 'bg-emerald-400';
  } else if (s === 'ACTIVE' || s === 'INVESTIGATING' || s === 'PROCESSING' || s === 'PARSING') {
    style = 'bg-cyan-950/60 text-cyan-400 border-cyan-800/60';
    dot = 'bg-cyan-400 animate-pulse';
  } else if (s === 'NEW' || s === 'UNACKNOWLEDGED' || s === 'PENDING') {
    style = 'bg-amber-950/60 text-amber-400 border-amber-800/60';
    dot = 'bg-amber-400';
  } else if (s === 'CONTAINED' || s === 'CORRELATED' || s === 'ACKNOWLEDGED' || s === 'DISPATCHED_N8N') {
    style = 'bg-indigo-950/60 text-indigo-300 border-indigo-800/60';
    dot = 'bg-indigo-400';
  } else if (s === 'FAILED' || s === 'DEGRADED' || s === 'CRITICAL' || s === 'ESCALATED') {
    style = 'bg-rose-950/60 text-rose-300 border-rose-800/70';
    dot = 'bg-rose-400 animate-pulse';
  }

  return (
    <span
      id={`status-badge-${status.toLowerCase().replace(/[^a-z0-9]/g, '-')}`}
      className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded text-[11px] font-mono font-medium border ${style}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dot}`} />
      <span>{status}</span>
    </span>
  );
};
