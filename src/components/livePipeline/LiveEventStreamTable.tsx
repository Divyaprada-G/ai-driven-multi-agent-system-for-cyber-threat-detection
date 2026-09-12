import React, { useState, useMemo } from 'react';
import {
  Search,
  Filter,
  Shield,
  ShieldAlert,
  AlertTriangle,
  Network,
  Cpu,
  Globe,
  Clock,
  ChevronRight,
  Sparkles,
  Layers,
  ArrowUpDown
} from 'lucide-react';
import { LiveSecurityEvent } from '../../types/livePipeline';

interface LiveEventStreamTableProps {
  events: LiveSecurityEvent[];
  onSelectEvent: (event: LiveSecurityEvent) => void;
}

export const LiveEventStreamTable: React.FC<LiveEventStreamTableProps> = ({
  events,
  onSelectEvent
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sourceFilter, setSourceFilter] = useState<'all' | 'network' | 'system' | 'application'>('all');
  const [threatFilter, setThreatFilter] = useState<'all' | 'threat' | 'benign'>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const filteredEvents = useMemo(() => {
    return events.filter((evt) => {
      // Source filter
      if (sourceFilter !== 'all' && evt.source !== sourceFilter) return false;

      // Threat filter
      const isThreat = evt.predictedClass && evt.predictedClass !== 'BENIGN';
      if (threatFilter === 'threat' && !isThreat) return false;
      if (threatFilter === 'benign' && isThreat) return false;

      // Severity filter
      if (severityFilter !== 'all' && evt.severity !== severityFilter) return false;

      // Search term filter
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase();
        const matchId = evt.eventId.toLowerCase().includes(term);
        const matchType = evt.eventType.toLowerCase().includes(term);
        const matchIp = (evt.sourceIp || '').toLowerCase().includes(term) || (evt.destinationIp || '').toLowerCase().includes(term);
        const matchPred = (evt.predictedClass || '').toLowerCase().includes(term);
        return matchId || matchType || matchIp || matchPred;
      }

      return true;
    });
  }, [events, sourceFilter, threatFilter, severityFilter, searchTerm]);

  const getSourceIcon = (source: string) => {
    switch (source) {
      case 'network':
        return <Network className="w-3.5 h-3.5 text-sky-400" />;
      case 'system':
        return <Cpu className="w-3.5 h-3.5 text-purple-400" />;
      case 'application':
        return <Globe className="w-3.5 h-3.5 text-amber-400" />;
      default:
        return <Shield className="w-3.5 h-3.5 text-slate-400" />;
    }
  };

  const getSeverityBadge = (severity?: string) => {
    switch (severity) {
      case 'CRITICAL':
        return <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30">CRITICAL</span>;
      case 'HIGH':
        return <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/30">HIGH</span>;
      case 'MEDIUM':
        return <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-300 border border-yellow-500/30">MEDIUM</span>;
      case 'LOW':
      default:
        return <span className="text-[10px] font-medium px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">LOW</span>;
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
      {/* Header & Filter Toolbar */}
      <div className="p-4 border-b border-slate-800 flex flex-col md:flex-row md:items-center justify-between gap-3 bg-slate-950/40">
        <div>
          <div className="flex items-center space-x-2">
            <h3 className="text-sm font-bold text-slate-100">Live Security Event Stream</h3>
            <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
              {filteredEvents.length} of {events.length}
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Real-time feed evaluated by Network, System, and Application agents with ML predictions.
          </p>
        </div>

        {/* Filter Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 transform -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              placeholder="Search IP, event, class..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 pr-3 py-1 bg-slate-900 border border-slate-700 rounded-lg text-xs text-slate-200 placeholder-slate-500 outline-none focus:border-sky-500 w-44"
            />
          </div>

          {/* Source Filter */}
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value as any)}
            className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1 outline-none focus:border-sky-500"
          >
            <option value="all">All Sources</option>
            <option value="network">Network</option>
            <option value="system">System</option>
            <option value="application">Application</option>
          </select>

          {/* Threat Filter */}
          <select
            value={threatFilter}
            onChange={(e) => setThreatFilter(e.target.value as any)}
            className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1 outline-none focus:border-sky-500"
          >
            <option value="all">All Classes</option>
            <option value="threat">Threats Only</option>
            <option value="benign">Benign Only</option>
          </select>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-lg px-2.5 py-1 outline-none focus:border-sky-500"
          >
            <option value="all">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Real-time Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-950/80 text-[11px] text-slate-400 font-semibold border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3">Time</th>
              <th className="py-2.5 px-3">Event ID</th>
              <th className="py-2.5 px-3">Source & Agent</th>
              <th className="py-2.5 px-3">Type & Target</th>
              <th className="py-2.5 px-3">ML Prediction</th>
              <th className="py-2.5 px-3">Prob / Conf</th>
              <th className="py-2.5 px-3">Risk Score</th>
              <th className="py-2.5 px-3">Severity</th>
              <th className="py-2.5 px-3">Latency</th>
              <th className="py-2.5 px-3 text-right">Traceability</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {filteredEvents.length === 0 ? (
              <tr>
                <td colSpan={10} className="py-10 text-center text-slate-500 font-sans">
                  {events.length === 0 ? (
                    <div>
                      <Clock className="w-8 h-8 text-slate-600 mx-auto mb-2 opacity-50" />
                      <p className="text-sm text-slate-400 font-medium">No live events captured yet</p>
                      <p className="text-xs text-slate-500 mt-0.5">Start the pipeline or simulator to begin streaming live security telemetry.</p>
                    </div>
                  ) : (
                    'No events match the selected filters.'
                  )}
                </td>
              </tr>
            ) : (
              filteredEvents.map((evt) => {
                const isThreat = evt.predictedClass && evt.predictedClass !== 'BENIGN';
                const timeStr = evt.processedAt
                  ? new Date(evt.processedAt).toLocaleTimeString()
                  : new Date(evt.receivedAt).toLocaleTimeString();

                return (
                  <tr
                    key={evt.eventId}
                    onClick={() => onSelectEvent(evt)}
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors group"
                  >
                    <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">{timeStr}</td>
                    <td className="py-2.5 px-3 text-slate-200 font-semibold whitespace-nowrap">
                      {evt.eventId}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <div className="flex items-center space-x-1.5 font-sans">
                        {getSourceIcon(evt.source)}
                        <span className="capitalize text-slate-300 font-medium">{evt.source}</span>
                      </div>
                      <span className="text-[10px] text-slate-500 font-sans block">{evt.agentType}</span>
                    </td>
                    <td className="py-2.5 px-3 font-sans max-w-xs truncate">
                      <div className="text-slate-200 truncate font-medium">{evt.eventType}</div>
                      <div className="text-[10px] text-slate-400 font-mono truncate">
                        {evt.sourceIp} → {evt.destinationIp}:{evt.destinationPort}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${
                        isThreat
                          ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30'
                          : 'bg-emerald-500/15 text-emerald-300 border border-emerald-500/30'
                      }`}>
                        {evt.predictedClass || 'BENIGN'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      {evt.confidence !== undefined ? (
                        <span className="text-slate-200">{(evt.confidence * 100).toFixed(1)}%</span>
                      ) : (
                        <span className="text-slate-500">N/A</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap font-bold">
                      {evt.riskScore !== undefined ? (
                        <span className={evt.riskScore >= 70 ? 'text-red-400' : evt.riskScore >= 40 ? 'text-amber-400' : 'text-emerald-400'}>
                          {evt.riskScore}
                        </span>
                      ) : (
                        <span className="text-slate-500">N/A</span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 whitespace-nowrap">
                      {getSeverityBadge(evt.severity)}
                    </td>
                    <td className="py-2.5 px-3 text-cyan-400 text-xs whitespace-nowrap">
                      {evt.latencyMs !== undefined ? `${evt.latencyMs}ms` : '0ms'}
                    </td>
                    <td className="py-2.5 px-3 text-right whitespace-nowrap">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectEvent(evt);
                        }}
                        className="px-2 py-1 rounded bg-sky-500/10 hover:bg-sky-500/20 text-sky-400 border border-sky-500/30 text-[10px] font-sans font-medium inline-flex items-center space-x-1 transition-colors"
                      >
                        <span>Lineage</span>
                        <ChevronRight className="w-3 h-3" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
