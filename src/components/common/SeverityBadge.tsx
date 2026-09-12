import React from 'react';
import { SeverityLevel } from '../../types';

interface SeverityBadgeProps {
  severity: SeverityLevel | string;
  size?: 'sm' | 'md' | 'lg';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'sm' }) => {
  const norm = (severity || '').toUpperCase() as SeverityLevel;

  let colorClasses = 'bg-slate-800 text-slate-300 border-slate-700';
  let dotColor = 'bg-slate-400';

  switch (norm) {
    case 'LOW':
      colorClasses = 'bg-blue-950/60 text-blue-400 border-blue-800/60';
      dotColor = 'bg-blue-400';
      break;
    case 'MEDIUM':
      colorClasses = 'bg-amber-950/60 text-amber-400 border-amber-800/60';
      dotColor = 'bg-amber-400';
      break;
    case 'HIGH':
      colorClasses = 'bg-orange-950/60 text-orange-400 border-orange-800/60';
      dotColor = 'bg-orange-400';
      break;
    case 'CRITICAL':
      colorClasses = 'bg-rose-950/70 text-rose-300 border-rose-700/80 shadow-[0_0_8px_rgba(244,63,94,0.25)]';
      dotColor = 'bg-rose-500 animate-pulse';
      break;
  }

  const sizeClasses = {
    sm: 'px-2 py-0.5 text-[11px]',
    md: 'px-2.5 py-1 text-xs',
    lg: 'px-3 py-1.5 text-sm font-semibold'
  }[size];

  return (
    <span
      id={`severity-badge-${norm.toLowerCase()}`}
      className={`inline-flex items-center gap-1.5 font-mono font-medium rounded border uppercase tracking-wider ${sizeClasses} ${colorClasses}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${dotColor}`} />
      <span>{norm}</span>
    </span>
  );
};
