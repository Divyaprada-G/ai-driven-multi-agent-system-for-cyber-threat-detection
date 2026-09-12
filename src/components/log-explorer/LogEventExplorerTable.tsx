import React, { useState, useMemo } from 'react';
import { LogEvent, LogFilterCriteria, LogType } from '../../types';
import { logRepository } from '../../services/logRepository';
import {
  Search,
  Filter,
  Eye,
  Download,
  Trash2,
  CheckCircle2,
  AlertCircle,
  Fingerprint,
  RefreshCw,
  Network,
  Server,
  Globe,
  FileCode,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

interface LogEventExplorerTableProps {
  events: LogEvent[];
  onSelectEvent: (event: LogEvent) => void;
  onClearData: () => void;
}

export const LogEventExplorerTable: React.FC<LogEventExplorerTableProps> = ({
  events,
  onSelectEvent,
  onClearData
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [selectedType, setSelectedType] = useState<string>('ALL');
  const [selectedValidation, setSelectedValidation] = useState<string>('ALL');
  const [hideDuplicates, setHideDuplicates] = useState(false);
  const [selectedSource, setSelectedSource] = useState<string>('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 12;

  // Extract unique sources
  const uniqueSources = useMemo(() => {
    const s = new Set<string>();
    for (const e of events) {
      if (e.source) s.add(e.source);
      if (e.normalizedFields?.sourceIp) s.add(e.normalizedFields.sourceIp);
      if (e.normalizedFields?.hostName) s.add(e.normalizedFields.hostName);
    }
    return Array.from(s).slice(0, 20);
  }, [events]);

  // Filter events
  const filteredEvents = useMemo(() => {
    return events.filter(e => {
      // Type filter
      if (selectedType !== 'ALL' && e.logType !== selectedType) {
        return false;
      }

      // Validation filter
      if (selectedValidation !== 'ALL') {
        if (selectedValidation === 'DUPLICATE') {
          if (!e.isDuplicate) return false;
        } else if (e.validation?.status !== selectedValidation) {
          return false;
        }
      }

      // Hide duplicates toggle
      if (hideDuplicates && e.isDuplicate) {
        return false;
      }

      // Source filter
      if (selectedSource !== 'ALL') {
        const nf = e.normalizedFields;
        const matchesSource =
          e.source === selectedSource ||
          nf?.sourceIp === selectedSource ||
          nf?.hostName === selectedSource;
        if (!matchesSource) return false;
      }

      // Search term filter
      if (searchTerm.trim() !== '') {
        const q = searchTerm.toLowerCase().trim();
        const nf = e.normalizedFields || {};
        const msg = (e.message || '').toLowerCase();
        const src = (e.source || '').toLowerCase();
        const raw = (e.rawData || '').toLowerCase();
        const id = (e.id || '').toLowerCase();
        const ip = (nf.sourceIp || '').toLowerCase();
        const dst = (nf.destinationIp || '').toLowerCase();
        const host = (nf.hostName || '').toLowerCase();
        const proc = (nf.processName || '').toLowerCase();
        const user = (nf.userName || '').toLowerCase();
        const endpoint = (nf.endpoint || '').toLowerCase();

        return (
          msg.includes(q) ||
          src.includes(q) ||
          raw.includes(q) ||
          id.includes(q) ||
          ip.includes(q) ||
          dst.includes(q) ||
          host.includes(q) ||
          proc.includes(q) ||
          user.includes(q) ||
          endpoint.includes(q)
        );
      }

      return true;
    });
  }, [events, selectedType, selectedValidation, hideDuplicates, selectedSource, searchTerm]);

  // Pagination
  const totalPages = Math.max(1, Math.ceil(filteredEvents.length / itemsPerPage));
  const paginatedEvents = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filteredEvents.slice(start, start + itemsPerPage);
  }, [filteredEvents, currentPage]);

  const handleExport = (format: 'json' | 'csv') => {
    const content = logRepository.exportEvents(format);
    const mime = format === 'json' ? 'application/json' : 'text/csv';
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `soc-telemetry-export.${format}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden space-y-0" id="log-event-explorer-table">
      {/* Table Header & Toolbar */}
      <div className="p-4 border-b border-slate-800 space-y-3">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <FileCode className="w-4 h-4 text-cyan-400" />
              Unified Security Event Stream
              <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-normal">
                {filteredEvents.length} of {events.length} Events
              </span>
            </h3>
            <p className="text-xs text-slate-400 mt-0.5">
              Normalized fields conforming to unified schema specifications across all 3 agent pipelines.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              id="btn-export-logs-json"
              onClick={() => handleExport('json')}
              disabled={events.length === 0}
              className="px-2.5 py-1.5 text-xs font-mono rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white flex items-center gap-1.5 transition-colors disabled:opacity-50"
              title="Export to JSON format"
            >
              <Download className="w-3.5 h-3.5" />
              JSON
            </button>

            <button
              id="btn-export-logs-csv"
              onClick={() => handleExport('csv')}
              disabled={events.length === 0}
              className="px-2.5 py-1.5 text-xs font-mono rounded-lg bg-slate-950 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white flex items-center gap-1.5 transition-colors disabled:opacity-50"
              title="Export to CSV format"
            >
              <Download className="w-3.5 h-3.5" />
              CSV
            </button>

            {events.length > 0 && (
              <button
                id="btn-clear-ingested-logs"
                onClick={onClearData}
                className="px-2.5 py-1.5 text-xs font-mono rounded-lg bg-rose-950/40 border border-rose-900/60 hover:bg-rose-900/60 text-rose-300 flex items-center gap-1.5 transition-colors"
                title="Reset all ingested logs and return to DEMO MODE"
              >
                <Trash2 className="w-3.5 h-3.5" />
                Reset to Demo
              </button>
            )}
          </div>
        </div>

        {/* Filter Controls Row */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-2.5 pt-1">
          {/* Search Box */}
          <div className="relative sm:col-span-2">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              id="input-filter-events-search"
              type="text"
              placeholder="Search IP, host, process, command, URI..."
              value={searchTerm}
              onChange={e => {
                setSearchTerm(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          {/* Log Type Filter */}
          <div>
            <select
              id="select-filter-domain"
              value={selectedType}
              onChange={e => {
                setSelectedType(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Domains</option>
              <option value="NETWORK">Network Domain</option>
              <option value="SYSTEM">System Domain</option>
              <option value="APPLICATION">Application Domain</option>
            </select>
          </div>

          {/* Validation Status Filter */}
          <div>
            <select
              id="select-filter-validation"
              value={selectedValidation}
              onChange={e => {
                setSelectedValidation(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Schema States</option>
              <option value="VALID">Valid Schema Only</option>
              <option value="INVALID">Schema Warnings / Errors</option>
              <option value="DUPLICATE">Duplicates Only</option>
            </select>
          </div>

          {/* Source Filter & Deduplicate Toggle */}
          <div className="flex items-center gap-2">
            <select
              id="select-filter-source"
              value={selectedSource}
              onChange={e => {
                setSelectedSource(e.target.value);
                setCurrentPage(1);
              }}
              className="w-full bg-slate-950 border border-slate-800 rounded-lg px-2 py-1.5 text-xs font-mono text-slate-300 focus:outline-none focus:border-cyan-500 truncate"
            >
              <option value="ALL">All Sources</option>
              {uniqueSources.map(s => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Deduplication & Active Filters Bar */}
        <div className="flex items-center justify-between text-xs font-mono text-slate-400 pt-1">
          <label className="flex items-center gap-2 cursor-pointer select-none">
            <input
              id="toggle-hide-duplicates"
              type="checkbox"
              checked={hideDuplicates}
              onChange={e => {
                setHideDuplicates(e.target.checked);
                setCurrentPage(1);
              }}
              className="rounded bg-slate-950 border-slate-700 text-cyan-500 focus:ring-0 focus:ring-offset-0"
            />
            <span className="text-slate-300">Hide FNV-1a Duplicates</span>
          </label>

          <span className="text-[11px] text-slate-500">
            Page {currentPage} of {totalPages}
          </span>
        </div>
      </div>

      {/* Events Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-950 text-slate-400 uppercase font-mono tracking-wider text-[11px] border-b border-slate-800">
            <tr>
              <th className="py-3 px-4">Timestamp</th>
              <th className="py-3 px-4">Domain</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Origin / Socket</th>
              <th className="py-3 px-4">Normalized Telemetry Message</th>
              <th className="py-3 px-4 text-right">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {paginatedEvents.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-slate-500 font-mono">
                  {events.length === 0 ? (
                    <div>
                      <p className="text-slate-400 font-sans font-medium">No real telemetry events ingested yet.</p>
                      <p className="text-xs text-slate-500 mt-1">Upload a log file or load a sample dataset above to view parsed events.</p>
                    </div>
                  ) : (
                    <div>No events match the current filter criteria.</div>
                  )}
                </td>
              </tr>
            ) : (
              paginatedEvents.map(event => {
                const nf = event.normalizedFields || {};
                const isValid = event.validation?.status === 'VALID';

                return (
                  <tr
                    key={event.id}
                    id={`row-event-${event.id.toLowerCase()}`}
                    onClick={() => onSelectEvent(event)}
                    className="hover:bg-slate-800/50 cursor-pointer transition-colors"
                  >
                    {/* Timestamp */}
                    <td className="py-2.5 px-4 text-slate-400 whitespace-nowrap text-[11px]">
                      {event.timestamp.replace('T', ' ').substring(0, 19)}
                    </td>

                    {/* Domain Badge */}
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold border ${
                          event.logType === 'NETWORK'
                            ? 'bg-blue-950/60 text-blue-400 border-blue-800'
                            : event.logType === 'SYSTEM'
                            ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800'
                            : 'bg-purple-950/60 text-purple-400 border-purple-800'
                        }`}
                      >
                        {event.logType === 'NETWORK' && <Network className="w-3 h-3" />}
                        {event.logType === 'SYSTEM' && <Server className="w-3 h-3" />}
                        {event.logType === 'APPLICATION' && <Globe className="w-3 h-3" />}
                        {event.logType}
                      </span>
                    </td>

                    {/* Validation & Duplicate Status */}
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <div className="flex items-center gap-1.5">
                        {isValid ? (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950/50 text-emerald-400 border border-emerald-800/80">
                            <CheckCircle2 className="w-3 h-3" />
                            VALID
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-semibold bg-rose-950/50 text-rose-400 border border-rose-800/80" title={event.validation?.errors?.join('; ')}>
                            <AlertCircle className="w-3 h-3" />
                            INVALID
                          </span>
                        )}

                        {event.isDuplicate && (
                          <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[10px] bg-amber-950/60 text-amber-400 border border-amber-800">
                            <Fingerprint className="w-3 h-3" />
                            DUP
                          </span>
                        )}
                      </div>
                    </td>

                    {/* Origin / Socket */}
                    <td className="py-2.5 px-4 text-cyan-400 whitespace-nowrap text-xs font-semibold">
                      {nf.sourceIp || nf.hostName || event.source}
                      {nf.sourcePort ? `:${nf.sourcePort}` : ''}
                    </td>

                    {/* Message Summary */}
                    <td className="py-2.5 px-4 max-w-md truncate text-slate-200 font-sans">
                      {event.message}
                    </td>

                    {/* Action */}
                    <td className="py-2.5 px-4 text-right whitespace-nowrap">
                      <button
                        id={`btn-inspect-event-${event.id.toLowerCase()}`}
                        onClick={e => {
                          e.stopPropagation();
                          onSelectEvent(event);
                        }}
                        className="p-1 rounded-md text-slate-400 hover:text-cyan-400 hover:bg-slate-800 transition-colors inline-flex items-center"
                        title="Inspect Event Fields & Raw Payload"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Footer */}
      {totalPages > 1 && (
        <div className="p-3 border-t border-slate-800 flex items-center justify-between text-xs font-mono text-slate-400 bg-slate-950/40">
          <div>
            Showing {(currentPage - 1) * itemsPerPage + 1} to{' '}
            {Math.min(currentPage * itemsPerPage, filteredEvents.length)} of {filteredEvents.length} events
          </div>
          <div className="flex items-center gap-1">
            <button
              id="btn-pagination-prev"
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              disabled={currentPage === 1}
              className="p-1 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 disabled:opacity-40 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="px-2">
              {currentPage} / {totalPages}
            </span>
            <button
              id="btn-pagination-next"
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              disabled={currentPage === totalPages}
              className="p-1 rounded bg-slate-900 border border-slate-800 hover:bg-slate-800 disabled:opacity-40 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
