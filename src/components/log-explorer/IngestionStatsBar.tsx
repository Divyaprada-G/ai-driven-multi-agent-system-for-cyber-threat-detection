import React from 'react';
import { RepositoryStats } from '../../types';
import {
  FileText,
  CheckCircle2,
  AlertCircle,
  Fingerprint,
  Network,
  Server,
  Globe,
  Clock
} from 'lucide-react';

interface IngestionStatsBarProps {
  stats: RepositoryStats;
}

export const IngestionStatsBar: React.FC<IngestionStatsBarProps> = ({ stats }) => {
  const validRate = stats.totalEvents > 0
    ? Math.round((stats.validEvents / stats.totalEvents) * 100)
    : 100;

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3" id="ingestion-stats-bar">
      {/* Total Ingested Events */}
      <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px] font-mono uppercase tracking-wider">Total Ingested</span>
          <FileText className="w-3.5 h-3.5 text-cyan-400" />
        </div>
        <div className="text-xl font-bold text-white font-mono">
          {stats.totalEvents.toLocaleString()}
        </div>
        <div className="text-[10px] text-slate-500 font-mono">
          Across {stats.ingestedFilesCount} file source(s)
        </div>
      </div>

      {/* Valid Events */}
      <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px] font-mono uppercase tracking-wider">Schema Valid</span>
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
        </div>
        <div className="text-xl font-bold text-emerald-400 font-mono">
          {stats.validEvents.toLocaleString()}
        </div>
        <div className="text-[10px] text-emerald-500/80 font-mono">
          {validRate}% conformity rate
        </div>
      </div>

      {/* Invalid / Malformed */}
      <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px] font-mono uppercase tracking-wider">Schema Warnings</span>
          <AlertCircle className="w-3.5 h-3.5 text-rose-400" />
        </div>
        <div className={`text-xl font-bold font-mono ${stats.invalidEvents > 0 ? 'text-rose-400' : 'text-slate-400'}`}>
          {stats.invalidEvents.toLocaleString()}
        </div>
        <div className="text-[10px] text-slate-500 font-mono">
          Malformed / RFC violations
        </div>
      </div>

      {/* Duplicates Detected */}
      <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px] font-mono uppercase tracking-wider">Deduplicated</span>
          <Fingerprint className="w-3.5 h-3.5 text-amber-400" />
        </div>
        <div className="text-xl font-bold text-amber-400 font-mono">
          {stats.duplicateEvents.toLocaleString()}
        </div>
        <div className="text-[10px] text-amber-500/80 font-mono">
          FNV-1a hash matching
        </div>
      </div>

      {/* Domain Distribution */}
      <div className="p-3 bg-slate-900 border border-slate-800 rounded-xl space-y-1 sm:col-span-2 lg:col-span-2">
        <div className="flex items-center justify-between text-slate-400">
          <span className="text-[11px] font-mono uppercase tracking-wider">Agent Queue Routing</span>
          <span className="text-[10px] text-cyan-400 font-mono">{stats.uniqueSources} Sources</span>
        </div>
        <div className="flex items-center gap-3 pt-0.5">
          <div className="flex items-center gap-1 text-xs font-mono text-blue-400">
            <Network className="w-3 h-3" />
            <span>Net: {stats.networkEvents}</span>
          </div>
          <div className="flex items-center gap-1 text-xs font-mono text-emerald-400">
            <Server className="w-3 h-3" />
            <span>Sys: {stats.systemEvents}</span>
          </div>
          <div className="flex items-center gap-1 text-xs font-mono text-purple-400">
            <Globe className="w-3 h-3" />
            <span>App: {stats.applicationEvents}</span>
          </div>
        </div>
        <div className="text-[10px] text-slate-500 font-mono flex items-center gap-1 truncate">
          <Clock className="w-3 h-3 shrink-0" />
          <span>Latest: {stats.lastEventTime ? stats.lastEventTime.replace('T', ' ').substring(0, 19) : 'Waiting'}</span>
        </div>
      </div>
    </div>
  );
};
