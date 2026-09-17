import React, { useState, useEffect, useMemo } from 'react';
import {
  Radio,
  Search,
  Filter,
  Play,
  Pause,
  RotateCcw,
  Clock,
  ShieldAlert,
  Server,
  Network,
  Globe,
  GitMerge,
  Cpu,
  Bell,
  Eye,
  ChevronRight,
  Database,
  SlidersHorizontal,
  X,
  ExternalLink
} from 'lucide-react';
import { livePipelineService } from '../../../services/livePipelineService';
import { LiveSecurityEvent } from '../../../types/livePipeline';
import { SeverityLevel } from '../../../types';

interface LiveSecurityEventsSectionProps {
  onSelectEvent?: (event: LiveSecurityEvent) => void;
}

export const LiveSecurityEventsSection: React.FC<LiveSecurityEventsSectionProps> = ({
  onSelectEvent
}) => {
  const [events, setEvents] = useState<LiveSecurityEvent[]>(livePipelineService.getEvents());
  const [isStreaming, setIsStreaming] = useState<boolean>(livePipelineService.getStatus().simulatorActive);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedAgent, setSelectedAgent] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedDetectionMethod, setSelectedDetectionMethod] = useState<string>('ALL');
  const [selectedDetailEvent, setSelectedDetailEvent] = useState<LiveSecurityEvent | null>(null);

  useEffect(() => {
    const unsub = livePipelineService.subscribe(() => {
      setEvents([...livePipelineService.getEvents()]);
      setIsStreaming(livePipelineService.getStatus().simulatorActive);
    });
    return () => unsub();
  }, []);

  const toggleStreaming = () => {
    if (isStreaming) {
      livePipelineService.stopSimulator();
      setIsStreaming(false);
    } else {
      livePipelineService.startSimulator({ eventRate: 1, mode: 'multistage' });
      setIsStreaming(true);
    }
  };

  const handleClear = () => {
    livePipelineService.clearEvents();
    setEvents([]);
  };

  // Agent Icon & Color Helper
  const getAgentBadge = (agent: string) => {
    const norm = (agent || '').toUpperCase();
    if (norm.includes('NET')) {
      return { label: 'Network Agent', icon: Network, color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30' };
    }
    if (norm.includes('SYS')) {
      return { label: 'System Agent', icon: Server, color: 'text-purple-400 bg-purple-500/10 border-purple-500/30' };
    }
    if (norm.includes('APP')) {
      return { label: 'Application Agent', icon: Globe, color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30' };
    }
    if (norm.includes('CORR')) {
      return { label: 'Event Correlation Agent', icon: GitMerge, color: 'text-indigo-400 bg-indigo-500/10 border-indigo-500/30' };
    }
    if (norm.includes('THREAT') || norm.includes('ML')) {
      return { label: 'Threat Detection Agent', icon: ShieldAlert, color: 'text-rose-400 bg-rose-500/10 border-rose-500/30' };
    }
    return { label: 'Alert Agent', icon: Bell, color: 'text-amber-400 bg-amber-500/10 border-amber-500/30' };
  };

  // Severity color badge helper
  const getSeverityBadge = (sev: string) => {
    const s = (sev || '').toUpperCase();
    switch (s) {
      case 'CRITICAL':
        return 'bg-rose-950/80 text-rose-300 border-rose-700 font-bold';
      case 'HIGH':
        return 'bg-amber-950/80 text-amber-300 border-amber-700 font-bold';
      case 'MEDIUM':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-700';
      case 'LOW':
        return 'bg-blue-950/80 text-blue-300 border-blue-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  // Detection method badge helper
  const getDetectionBadge = (method: string) => {
    const m = (method || '').toUpperCase();
    if (m.includes('ML') || m.includes('MACHINE')) {
      return { label: 'Machine Learning', style: 'bg-indigo-950/80 text-indigo-300 border-indigo-700' };
    }
    if (m.includes('RULE') || m.includes('SIGNATURE')) {
      return { label: 'Rule-Based', style: 'bg-cyan-950/80 text-cyan-300 border-cyan-700' };
    }
    if (m.includes('CORR') || m.includes('GRAPH')) {
      return { label: 'Correlation Graph', style: 'bg-purple-950/80 text-purple-300 border-purple-700' };
    }
    return { label: method || 'Multi-Layer', style: 'bg-slate-800 text-slate-300 border-slate-700' };
  };

  // Data Source Provenance helper
  const getSourceTypeBadge = (sourceType?: string) => {
    switch (sourceType) {
      case 'LIVE_INGEST':
        return { text: 'LIVE INGEST', bg: 'bg-emerald-950/80 text-emerald-300 border-emerald-700' };
      case 'UPLOADED_BENCHMARK':
        return { text: 'UPLOADED DATA', bg: 'bg-cyan-950/80 text-cyan-300 border-cyan-700' };
      case 'SIMULATED':
      default:
        return { text: 'SIMULATED SCENARIO', bg: 'bg-slate-800 text-slate-300 border-slate-700' };
    }
  };

  // Filtered Events
  const filteredEvents = useMemo(() => {
    return events.filter(evt => {
      // Search filter
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        const match =
          evt.id.toLowerCase().includes(q) ||
          evt.eventType.toLowerCase().includes(q) ||
          evt.source.toLowerCase().includes(q) ||
          evt.agentName.toLowerCase().includes(q) ||
          (evt.details && JSON.stringify(evt.details).toLowerCase().includes(q));
        if (!match) return false;
      }
      // Agent filter
      if (selectedAgent !== 'ALL' && evt.agentName !== selectedAgent) {
        return false;
      }
      // Severity filter
      if (selectedSeverity !== 'ALL' && evt.severity !== selectedSeverity) {
        return false;
      }
      // Detection method filter
      if (selectedDetectionMethod !== 'ALL') {
        const m = (evt.detectionMethod || '').toUpperCase();
        if (selectedDetectionMethod === 'ML' && !m.includes('ML') && !m.includes('MACHINE')) return false;
        if (selectedDetectionMethod === 'RULE' && !m.includes('RULE') && !m.includes('SIGNATURE')) return false;
        if (selectedDetectionMethod === 'CORR' && !m.includes('CORR')) return false;
      }
      return true;
    });
  }, [events, searchTerm, selectedAgent, selectedSeverity, selectedDetectionMethod]);

  return (
    <div className="space-y-4 font-mono" id="dashboard-section-live-events">
      {/* Header & Streaming Controls Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xl">
        <div>
          <div className="flex items-center gap-2">
            <span className={`w-2.5 h-2.5 rounded-full ${isStreaming ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <Radio className="w-4 h-4 text-cyan-400" />
              Live Security Events Timeline
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700">
              {filteredEvents.length} of {events.length} events
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Chronological event stream with agent origin, event type, source address, severity, and detection method.
          </p>
        </div>

        {/* Live Simulator Playback Controls */}
        <div className="flex items-center gap-2">
          <button
            id="btn-live-stream-toggle"
            onClick={toggleStreaming}
            className={`px-3 py-1.5 rounded-lg text-xs font-bold transition-all flex items-center gap-1.5 ${
              isStreaming
                ? 'bg-amber-600 hover:bg-amber-500 text-white'
                : 'bg-emerald-600 hover:bg-emerald-500 text-white'
            }`}
          >
            {isStreaming ? (
              <>
                <Pause className="w-3.5 h-3.5" />
                <span>Pause Stream</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5" />
                <span>Start Stream</span>
              </>
            )}
          </button>

          <button
            id="btn-live-stream-clear"
            onClick={handleClear}
            className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs transition-colors flex items-center gap-1"
            title="Clear Event Stream Buffer"
          >
            <RotateCcw className="w-3 h-3 text-slate-400" />
            <span>Clear</span>
          </button>
        </div>
      </div>

      {/* Filter & Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center gap-2 text-xs">
        {/* Search */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
          <input
            id="input-search-live-events"
            type="text"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            placeholder="Search IP, event type, agent, or payload..."
            className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 text-xs font-mono"
          />
        </div>

        {/* Agent Filter */}
        <div className="flex items-center gap-1">
          <span className="text-slate-500 text-[11px]">Agent:</span>
          <select
            id="select-filter-agent"
            value={selectedAgent}
            onChange={e => setSelectedAgent(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Agents</option>
            <option value="NETWORK_AGENT">Network Agent</option>
            <option value="SYSTEM_AGENT">System Agent</option>
            <option value="APPLICATION_AGENT">Application Agent</option>
            <option value="CORRELATION_AGENT">Event Correlation Agent</option>
            <option value="THREAT_DETECTION_AGENT">Threat Detection Agent</option>
            <option value="ALERT_AGENT">Alert Agent</option>
          </select>
        </div>

        {/* Severity Filter */}
        <div className="flex items-center gap-1">
          <span className="text-slate-500 text-[11px]">Severity:</span>
          <select
            id="select-filter-severity"
            value={selectedSeverity}
            onChange={e => setSelectedSeverity(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>

        {/* Detection Method Filter */}
        <div className="flex items-center gap-1">
          <span className="text-slate-500 text-[11px]">Method:</span>
          <select
            id="select-filter-method"
            value={selectedDetectionMethod}
            onChange={e => setSelectedDetectionMethod(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Methods</option>
            <option value="ML">Machine Learning</option>
            <option value="RULE">Rule-Based Signatures</option>
            <option value="CORR">Correlation Graph</option>
          </select>
        </div>

        {(searchTerm || selectedAgent !== 'ALL' || selectedSeverity !== 'ALL' || selectedDetectionMethod !== 'ALL') && (
          <button
            onClick={() => {
              setSearchTerm('');
              setSelectedAgent('ALL');
              setSelectedSeverity('ALL');
              setSelectedDetectionMethod('ALL');
            }}
            className="px-2 py-1 text-[11px] text-cyan-400 hover:text-cyan-300 underline flex items-center gap-1"
          >
            <X className="w-3 h-3" />
            Reset Filters
          </button>
        )}
      </div>

      {/* Events Table / Timeline List */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs" id="table-live-security-events">
            <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 text-[11px] uppercase tracking-wider">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-4">Agent Name</th>
                <th className="py-3 px-4">Event Type</th>
                <th className="py-3 px-4">Source</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Detection Method</th>
                <th className="py-3 px-4">Data Source</th>
                <th className="py-3 px-3 text-right">Details</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 font-mono">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-500">
                    <Radio className="w-8 h-8 text-slate-600 mx-auto mb-2 opacity-50" />
                    <p className="text-sm text-slate-400">No events match the selected criteria.</p>
                    <p className="text-xs text-slate-500 mt-1">
                      {isStreaming
                        ? 'Waiting for next simulated packet...'
                        : 'Click "Start Stream" above to begin telemetry playback or ingest new logs.'}
                    </p>
                  </td>
                </tr>
              ) : (
                filteredEvents.map(evt => {
                  const agentBadge = getAgentBadge(evt.agentName);
                  const AgentIcon = agentBadge.icon;
                  const sevBadge = getSeverityBadge(evt.severity);
                  const detBadge = getDetectionBadge(evt.detectionMethod || 'RULE_BASED');
                  const srcType = getSourceTypeBadge(evt.sourceType);

                  return (
                    <tr
                      key={evt.id}
                      onClick={() => {
                        setSelectedDetailEvent(evt);
                        if (onSelectEvent) onSelectEvent(evt);
                      }}
                      className="hover:bg-slate-800/50 transition-colors cursor-pointer group"
                    >
                      {/* Timestamp */}
                      <td className="py-2.5 px-4 whitespace-nowrap text-slate-300">
                        <div className="flex items-center gap-1.5">
                          <Clock className="w-3 h-3 text-slate-500" />
                          <span>{evt.timestamp.split('T')[1] ? evt.timestamp.split('T')[1].split('.')[0] : evt.timestamp}</span>
                        </div>
                      </td>

                      {/* Agent Name */}
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        <div className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-[11px] ${agentBadge.color}`}>
                          <AgentIcon className="w-3 h-3" />
                          <span>{agentBadge.label}</span>
                        </div>
                      </td>

                      {/* Event Type */}
                      <td className="py-2.5 px-4 text-white font-semibold">
                        <span className="group-hover:text-cyan-400 transition-colors">
                          {evt.eventType}
                        </span>
                      </td>

                      {/* Source */}
                      <td className="py-2.5 px-4 whitespace-nowrap font-mono text-slate-300">
                        <span className="px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-[11px]">
                          {evt.source}
                        </span>
                      </td>

                      {/* Severity */}
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded border text-[10px] uppercase ${sevBadge}`}>
                          {evt.severity}
                        </span>
                      </td>

                      {/* Detection Method */}
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded border text-[10px] ${detBadge.style}`}>
                          {detBadge.label}
                        </span>
                      </td>

                      {/* Data Source Provenance */}
                      <td className="py-2.5 px-4 whitespace-nowrap">
                        <span className={`px-2 py-0.5 rounded border text-[9px] font-bold ${srcType.bg}`}>
                          {srcType.text}
                        </span>
                      </td>

                      {/* Details button */}
                      <td className="py-2.5 px-3 text-right whitespace-nowrap">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedDetailEvent(evt);
                          }}
                          className="p-1 rounded hover:bg-slate-700 text-slate-400 hover:text-cyan-400 transition-colors"
                          title="View Raw Event Dossier"
                        >
                          <Eye className="w-3.5 h-3.5" />
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

      {/* Modal for Event Detail & Raw Evidence */}
      {selectedDetailEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-5 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Radio className="w-4 h-4 text-cyan-400" />
                <h3 className="text-sm font-bold text-white">Event Telemetry Details</h3>
                <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 text-[10px]">
                  {selectedDetailEvent.id}
                </span>
              </div>
              <button
                onClick={() => setSelectedDetailEvent(null)}
                className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950 p-3 rounded-lg border border-slate-800">
              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Agent</span>
                <span className="text-slate-200 font-bold">{selectedDetailEvent.agentName}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Severity</span>
                <span className={`px-1.5 py-0.5 rounded border text-[10px] ${getSeverityBadge(selectedDetailEvent.severity)}`}>
                  {selectedDetailEvent.severity}
                </span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Source</span>
                <span className="text-slate-200">{selectedDetailEvent.source}</span>
              </div>
              <div>
                <span className="text-[10px] text-slate-500 uppercase block">Method</span>
                <span className="text-cyan-400">{selectedDetailEvent.detectionMethod || 'RULE_BASED'}</span>
              </div>
            </div>

            <div>
              <span className="text-[11px] text-slate-400 font-semibold uppercase block mb-1">
                Event Description & Payload
              </span>
              <div className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-300 font-mono text-[11px] break-words whitespace-pre-wrap">
                {selectedDetailEvent.description || selectedDetailEvent.eventType}
              </div>
            </div>

            {selectedDetailEvent.details && (
              <div>
                <span className="text-[11px] text-slate-400 font-semibold uppercase block mb-1">
                  Structured Normalized Telemetry
                </span>
                <pre className="p-3 bg-slate-950 border border-slate-800 rounded-lg text-slate-400 font-mono text-[11px] overflow-x-auto">
                  {JSON.stringify(selectedDetailEvent.details, null, 2)}
                </pre>
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                onClick={() => setSelectedDetailEvent(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-bold transition-colors"
              >
                Close Dossier
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
