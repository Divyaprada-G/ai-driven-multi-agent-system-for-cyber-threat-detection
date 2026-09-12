import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  id: string;
  title: string;
  value: string | number;
  subtitle?: string;
  change?: string;
  isIncreaseNegative?: boolean;
  icon: LucideIcon;
  variant?: 'default' | 'critical' | 'warning' | 'info' | 'emerald';
}

export const StatCard: React.FC<StatCardProps> = ({
  id,
  title,
  value,
  subtitle,
  change,
  isIncreaseNegative,
  icon: Icon,
  variant = 'default'
}) => {
  const variantStyles = {
    default: 'border-slate-800 bg-slate-900/70 hover:border-slate-700 text-slate-100',
    critical: 'border-rose-900/50 bg-rose-950/20 hover:border-rose-800 text-rose-200',
    warning: 'border-amber-900/50 bg-amber-950/20 hover:border-amber-800 text-amber-200',
    info: 'border-cyan-900/50 bg-cyan-950/20 hover:border-cyan-800 text-cyan-200',
    emerald: 'border-emerald-900/50 bg-emerald-950/20 hover:border-emerald-800 text-emerald-200'
  }[variant];

  const iconColors = {
    default: 'text-slate-400 bg-slate-800/80',
    critical: 'text-rose-400 bg-rose-900/40 border border-rose-800/50',
    warning: 'text-amber-400 bg-amber-900/40 border border-amber-800/50',
    info: 'text-cyan-400 bg-cyan-900/40 border border-cyan-800/50',
    emerald: 'text-emerald-400 bg-emerald-900/40 border border-emerald-800/50'
  }[variant];

  return (
    <div
      id={id}
      className={`relative p-4 rounded-xl border backdrop-blur-sm transition-all duration-200 ${variantStyles}`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="space-y-1">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400 font-mono">
            {title}
          </p>
          <div className="text-2xl font-bold font-mono tracking-tight text-white">
            {typeof value === 'number' ? value.toLocaleString() : value}
          </div>
        </div>
        <div className={`p-2.5 rounded-lg ${iconColors}`}>
          <Icon className="w-5 h-5 shrink-0" />
        </div>
      </div>

      {(subtitle || change) && (
        <div className="mt-3 pt-2.5 border-t border-slate-800/60 flex items-center justify-between text-xs text-slate-400">
          {subtitle && <span className="truncate">{subtitle}</span>}
          {change && (
            <span
              className={`font-mono text-[11px] font-medium ml-auto ${
                isIncreaseNegative
                  ? change.startsWith('+')
                    ? 'text-rose-400'
                    : 'text-emerald-400'
                  : 'text-slate-400'
              }`}
            >
              {change}
            </span>
          )}
        </div>
      )}
    </div>
  );
};
