import React, { useState } from 'react';
import { SeverityBadge } from '../common/SeverityBadge';
import { Search, Eye, Filter } from 'lucide-react';
import { SeverityLevel } from '../../types';

export interface RecentEventItem {
  id: string;
  timestamp: string;
  source: string;
  agent: string;
  eventType: string;
  severity: SeverityLevel;
  riskScore: number;
  status: string;
  action: string;
  detail?: string;
}

interface RecentEventsTableProps {
  events: RecentEventItem[];
  onSelectEvent?: (event: RecentEventItem) => void;
}

export const RecentEventsTable: React.FC<RecentEventsTableProps> = ({
  events,
  onSelectEvent
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [selectedEventModal, setSelectedEventModal] = useState<RecentEventItem | null>(null);

  const filteredEvents = events.filter(evt => {
    const matchesSearch =
      evt.eventType.toLowerCase().includes(searchTerm.toLowerCase()) ||
      evt.source.toLowerCase().includes(searchTerm.toLowerCase()) ||
      evt.agent.toLowerCase().includes(searchTerm.toLowerCase()) ||
      evt.id.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesSeverity =
      severityFilter === 'ALL' || evt.severity === severityFilter;

    return matchesSearch && matchesSeverity;
  });

  const handleOpenDetail = (evt: RecentEventItem) => {
    if (onSelectEvent) {
      onSelectEvent(evt);
    } else {
      setSelectedEventModal(evt);
    }
  };

  return (
    <div className="w-full bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden backdrop-blur-sm" id="table-recent-security-events">
      {/* Table Controls */}
      <div className="p-4 border-b border-slate-800 flex flex-col sm:flex-row gap-3 sm:items-center sm:justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            id="input-search-security-events"
            type="text"
            placeholder="Search events, sources, agents, or indicators..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-4 py-1.5 text-xs bg-slate-950 border border-slate-800 rounded-lg text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <span className="text-xs text-slate-400 font-mono">Severity:</span>
          <select
            id="select-severity-filter"
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="text-xs font-mono bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-300 border-collapse">
          <thead className="bg-slate-950/70 text-slate-400 uppercase font-mono tracking-wider text-[11px] border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">Event ID / Time</th>
              <th className="py-3 px-4">Source</th>
              <th className="py-3 px-4">Agent</th>
              <th className="py-3 px-4">Event Type</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Risk Score</th>
              <th className="py-3 px-4">Pipeline Status</th>
              <th className="py-3 px-4">Action Taken</th>
              <th className="py-3 px-4 text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {filteredEvents.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-8 text-center text-slate-500">
                  No security events matching current criteria.
                </td>
              </tr>
            ) : (
              filteredEvents.map(evt => (
                <tr
                  key={evt.id}
                  id={`row-event-${evt.id.toLowerCase()}`}
                  className="hover:bg-slate-800/40 transition-colors"
                >
                  <td className="py-3 px-4">
                    <div className="font-semibold text-slate-200">{evt.id}</div>
                    <div className="text-[10px] text-slate-500">{evt.timestamp}</div>
                  </td>

                  <td className="py-3 px-4 max-w-[160px] truncate text-slate-300">
                    {evt.source}
                  </td>

                  <td className="py-3 px-4">
                    <span className="inline-flex items-center gap-1.5 text-xs text-cyan-400">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
                      {evt.agent}
                    </span>
                  </td>

                  <td className="py-3 px-4 font-sans font-medium text-slate-100">
                    {evt.eventType}
                  </td>

                  <td className="py-3 px-4">
                    <SeverityBadge severity={evt.severity} />
                  </td>

                  <td className="py-3 px-4">
                    <span
                      className={`font-bold ${
                        evt.riskScore >= 85
                          ? 'text-rose-400'
                          : evt.riskScore >= 70
                          ? 'text-orange-400'
                          : evt.riskScore >= 50
                          ? 'text-amber-400'
                          : 'text-blue-400'
                      }`}
                    >
                      {evt.riskScore}/100
                    </span>
                  </td>

                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded text-[11px] bg-slate-800 text-slate-300 border border-slate-700">
                      {evt.status}
                    </span>
                  </td>

                  <td className="py-3 px-4 text-xs font-sans text-slate-400">
                    {evt.action}
                  </td>

                  <td className="py-3 px-4 text-right">
                    <button
                      id={`btn-inspect-${evt.id.toLowerCase()}`}
                      onClick={() => handleOpenDetail(evt)}
                      className="p-1.5 rounded-lg text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-colors inline-flex items-center gap-1"
                      title="Inspect Event Payload"
                    >
                      <Eye className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Internal Modal Fallback for Event Details */}
      {selectedEventModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-700 rounded-xl max-w-lg w-full p-5 shadow-2xl space-y-4">
            <div className="flex items-start justify-between">
              <div>
                <span className="text-xs font-mono text-cyan-400">
                  {selectedEventModal.id} • {selectedEventModal.agent}
                </span>
                <h3 className="text-base font-bold text-white mt-1">
                  {selectedEventModal.eventType}
                </h3>
              </div>
              <SeverityBadge severity={selectedEventModal.severity} size="md" />
            </div>

            <div className="space-y-2 text-xs font-mono bg-slate-950 p-3 rounded-lg border border-slate-800 text-slate-300">
              <div>
                <span className="text-slate-500">Timestamp: </span>
                {selectedEventModal.timestamp}
              </div>
              <div>
                <span className="text-slate-500">Source: </span>
                {selectedEventModal.source}
              </div>
              <div>
                <span className="text-slate-500">Calculated Risk: </span>
                <span className="text-rose-400 font-bold">{selectedEventModal.riskScore}/100</span>
              </div>
              <div>
                <span className="text-slate-500">Action: </span>
                {selectedEventModal.action}
              </div>
            </div>

            {selectedEventModal.detail && (
              <div className="text-xs text-slate-300 space-y-1">
                <span className="font-semibold text-slate-200">Detection Telemetry:</span>
                <p className="p-3 bg-slate-950/70 border border-slate-800 rounded font-mono text-[11px] text-slate-300 leading-relaxed">
                  {selectedEventModal.detail}
                </p>
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-slate-800">
              <button
                id="btn-close-event-modal"
                onClick={() => setSelectedEventModal(null)}
                className="px-4 py-1.5 text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg transition-colors"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
