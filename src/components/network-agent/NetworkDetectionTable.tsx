import React, { useState, useMemo } from 'react';
import { NetworkAgentResult, SeverityLevel, NetworkAgentClassification } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import { Search, Filter, Download, ExternalLink, ShieldAlert, AlertTriangle, CheckCircle2 } from 'lucide-react';

interface NetworkDetectionTableProps {
  results: NetworkAgentResult[];
  onSelectResult: (result: NetworkAgentResult) => void;
}

export const NetworkDetectionTable: React.FC<NetworkDetectionTableProps> = ({
  results,
  onSelectResult
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [classificationFilter, setClassificationFilter] = useState<string>('ALL');
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const filteredResults = useMemo(() => {
    return results.filter(r => {
      // Search term
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase();
        const matchesIp = r.sourceIp.toLowerCase().includes(term) || r.destinationIp.toLowerCase().includes(term);
        const matchesDet = r.detection.toLowerCase().includes(term) || r.threatType.toLowerCase().includes(term);
        const matchesProto = (r.protocol || '').toLowerCase().includes(term);
        if (!matchesIp && !matchesDet && !matchesProto) return false;
      }

      // Severity filter
      if (severityFilter !== 'ALL' && r.severity !== severityFilter) {
        return false;
      }

      // Classification filter
      if (classificationFilter !== 'ALL' && r.classification !== classificationFilter) {
        return false;
      }

      return true;
    });
  }, [results, searchTerm, severityFilter, classificationFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredResults.length / pageSize));
  const currentPageResults = filteredResults.slice((page - 1) * pageSize, page * pageSize);

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(results, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `network-agent-detections-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-4" id="network-detection-table-card">
      {/* Controls Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-cyan-400" />
            Network Agent Detection Results
          </h3>
          <p className="text-xs text-slate-400 mt-0.5 font-mono">
            {filteredResults.length} detections identified ({results.filter(r => r.threatDetected).length} threats)
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Search box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              id="input-search-detections"
              value={searchTerm}
              onChange={e => {
                setSearchTerm(e.target.value);
                setPage(1);
              }}
              placeholder="Search IP, port, finding..."
              className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-950/80 border border-slate-700 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono w-44"
            />
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1 bg-slate-950/80 border border-slate-700 rounded-lg px-2 py-1">
            <Filter className="w-3 h-3 text-slate-400" />
            <select
              id="select-filter-severity"
              value={severityFilter}
              onChange={e => {
                setSeverityFilter(e.target.value);
                setPage(1);
              }}
              className="bg-transparent text-xs text-slate-300 font-mono focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Classification Filter */}
          <div className="flex items-center gap-1 bg-slate-950/80 border border-slate-700 rounded-lg px-2 py-1">
            <select
              id="select-filter-classification"
              value={classificationFilter}
              onChange={e => {
                setClassificationFilter(e.target.value);
                setPage(1);
              }}
              className="bg-transparent text-xs text-slate-300 font-mono focus:outline-none cursor-pointer"
            >
              <option value="ALL">All Statuses</option>
              <option value="THREAT">Threats Only</option>
              <option value="SUSPICIOUS">Suspicious Only</option>
              <option value="BENIGN">Benign Only</option>
            </select>
          </div>

          {/* Export JSON */}
          <button
            id="btn-export-network-detections"
            onClick={handleExportJson}
            title="Export Detections to JSON"
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-mono border border-slate-700 transition-colors"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span className="hidden sm:inline">Export</span>
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto border border-slate-800/80 rounded-lg">
        <table className="w-full text-left text-xs font-mono text-slate-300" id="table-network-detections">
          <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3">Timestamp</th>
              <th className="py-2.5 px-3">Source IP</th>
              <th className="py-2.5 px-3">Destination IP</th>
              <th className="py-2.5 px-3">Proto / Ports</th>
              <th className="py-2.5 px-3">Detection</th>
              <th className="py-2.5 px-3">Severity</th>
              <th className="py-2.5 px-3">Confidence</th>
              <th className="py-2.5 px-3">Classification</th>
              <th className="py-2.5 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {currentPageResults.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-8 text-center text-slate-500">
                  No matching detections found.
                </td>
              </tr>
            ) : (
              currentPageResults.map(r => (
                <tr
                  key={r.id}
                  onClick={() => onSelectResult(r)}
                  className="hover:bg-slate-800/40 cursor-pointer transition-colors group"
                >
                  <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">
                    {r.timestamp ? r.timestamp.replace('T', ' ').substring(0, 19) : '-'}
                  </td>
                  <td className="py-2.5 px-3 font-semibold text-white group-hover:text-cyan-400 transition-colors whitespace-nowrap">
                    {r.sourceIp}
                  </td>
                  <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">
                    {r.destinationIp}
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    <span className="px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-[10px] text-cyan-300 mr-1.5">
                      {r.protocol || 'TCP'}
                    </span>
                    <span className="text-slate-400 text-[11px]">
                      {r.ports && r.ports.length > 1
                        ? `${r.ports.length} ports`
                        : r.destinationPort || '-'}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 font-sans font-medium text-slate-100 max-w-[220px] truncate">
                    {r.detection}
                  </td>
                  <td className="py-2.5 px-3">
                    <SeverityBadge severity={r.severity} />
                  </td>
                  <td className="py-2.5 px-3">
                    <span className="text-cyan-400 font-bold">
                      {(r.confidence * 100).toFixed(0)}%
                    </span>
                  </td>
                  <td className="py-2.5 px-3 whitespace-nowrap">
                    {r.classification === 'THREAT' ? (
                      <span className="inline-flex items-center gap-1 text-rose-400 text-[11px] font-bold">
                        <AlertTriangle className="w-3 h-3" />
                        THREAT
                      </span>
                    ) : r.classification === 'SUSPICIOUS' ? (
                      <span className="inline-flex items-center gap-1 text-amber-400 text-[11px]">
                        <AlertTriangle className="w-3 h-3" />
                        SUSPICIOUS
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-emerald-400 text-[11px]">
                        <CheckCircle2 className="w-3 h-3" />
                        BENIGN
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-3 text-right">
                    <button
                      id={`btn-inspect-${r.id.toLowerCase()}`}
                      onClick={e => {
                        e.stopPropagation();
                        onSelectResult(r);
                      }}
                      className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 hover:bg-cyan-950/80 border border-slate-700 hover:border-cyan-500/50 text-[11px] text-cyan-400 transition-colors"
                    >
                      <span>Inspect</span>
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between pt-2 text-xs font-mono text-slate-400">
          <div>
            Showing {(page - 1) * pageSize + 1} to{' '}
            {Math.min(page * pageSize, filteredResults.length)} of {filteredResults.length} detections
          </div>
          <div className="flex items-center gap-1.5">
            <button
              id="btn-table-prev-page"
              disabled={page <= 1}
              onClick={() => setPage(p => Math.max(1, p - 1))}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed border border-slate-700 text-slate-200"
            >
              Previous
            </button>
            <span className="px-2 text-slate-300">
              Page {page} of {totalPages}
            </span>
            <button
              id="btn-table-next-page"
              disabled={page >= totalPages}
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed border border-slate-700 text-slate-200"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
