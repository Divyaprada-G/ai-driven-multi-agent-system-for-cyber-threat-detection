import React, { useState, useMemo } from 'react';
import { SystemAgentResult } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';
import { Search, Download, ExternalLink, ShieldAlert, AlertTriangle } from 'lucide-react';

interface SystemDetectionTableProps {
  results: SystemAgentResult[];
  onSelectResult: (result: SystemAgentResult) => void;
}

export const SystemDetectionTable: React.FC<SystemDetectionTableProps> = ({
  results,
  onSelectResult
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [classificationFilter, setClassificationFilter] = useState<string>('ALL');
  const [threatTypeFilter, setThreatTypeFilter] = useState<string>('ALL');
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const filteredResults = useMemo(() => {
    return results.filter(r => {
      // Search term
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase();
        const matchesUser = r.username.toLowerCase().includes(term);
        const matchesHost = r.host.toLowerCase().includes(term);
        const matchesDet = r.detection.toLowerCase().includes(term) || r.threatType.toLowerCase().includes(term);
        const matchesCmd = (r.commandLine || '').toLowerCase().includes(term) || (r.processName || '').toLowerCase().includes(term);
        const matchesIp = (r.sourceIp || '').toLowerCase().includes(term);
        if (!matchesUser && !matchesHost && !matchesDet && !matchesCmd && !matchesIp) return false;
      }

      // Severity filter
      if (severityFilter !== 'ALL' && r.severity !== severityFilter) {
        return false;
      }

      // Classification filter
      if (classificationFilter !== 'ALL' && r.classification !== classificationFilter) {
        return false;
      }

      // Threat Type filter
      if (threatTypeFilter !== 'ALL' && r.threatType !== threatTypeFilter) {
        return false;
      }

      return true;
    });
  }, [results, searchTerm, severityFilter, classificationFilter, threatTypeFilter]);

  const totalPages = Math.max(1, Math.ceil(filteredResults.length / pageSize));
  const currentPageResults = filteredResults.slice((page - 1) * pageSize, page * pageSize);

  const handleExportJson = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(results, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `system-agent-detections-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-4" id="system-detection-table-card">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-base font-bold text-white font-mono">
              System Agent Detection Findings
            </h3>
            <span className="px-2 py-0.5 rounded-full text-xs font-mono bg-emerald-950/80 text-emerald-300 border border-emerald-800">
              {results.length} Total Detections
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Structured host-level findings with confidence scores, forensic evidence, and explainability paths.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            id="btn-export-system-json"
            onClick={handleExportJson}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-mono bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Findings (JSON)</span>
          </button>
        </div>
      </div>

      {/* Filter Controls Bar */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 pt-2">
        {/* Search */}
        <div className="relative">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            id="input-search-system-detections"
            type="text"
            placeholder="Search host, user, command, pattern..."
            value={searchTerm}
            onChange={e => {
              setSearchTerm(e.target.value);
              setPage(1);
            }}
            className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
          />
        </div>

        {/* Severity */}
        <div>
          <select
            id="select-system-severity-filter"
            value={severityFilter}
            onChange={e => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
            className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical Severity</option>
            <option value="HIGH">High Severity</option>
            <option value="MEDIUM">Medium Severity</option>
            <option value="LOW">Low Severity</option>
          </select>
        </div>

        {/* Classification */}
        <div>
          <select
            id="select-system-classification-filter"
            value={classificationFilter}
            onChange={e => {
              setClassificationFilter(e.target.value);
              setPage(1);
            }}
            className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Classifications</option>
            <option value="THREAT">Threats Only</option>
            <option value="SUSPICIOUS">Suspicious Only</option>
            <option value="BENIGN">Benign Only</option>
          </select>
        </div>

        {/* Threat Type */}
        <div>
          <select
            id="select-system-threat-type-filter"
            value={threatTypeFilter}
            onChange={e => {
              setThreatTypeFilter(e.target.value);
              setPage(1);
            }}
            className="w-full px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-xs font-mono text-slate-300 focus:outline-none focus:border-emerald-500"
          >
            <option value="ALL">All Finding Categories</option>
            <option value="SUSPICIOUS_AUTH_SEQUENCE">Auth Sequence (Success After Failures)</option>
            <option value="BRUTE_FORCE">Brute Force Activity</option>
            <option value="REPEATED_AUTH_FAILURES">Repeated Auth Failures</option>
            <option value="PRIVILEGE_ESCALATION">Privilege Escalation</option>
            <option value="SUSPICIOUS_PROCESS">Suspicious Process / LOLBIN</option>
            <option value="UNUSUAL_HOST_ACTIVITY">Unusual Host Activity</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto border border-slate-800 rounded-lg">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="bg-slate-950/90 text-slate-400 font-mono uppercase text-[11px] border-b border-slate-800">
              <th className="py-3 px-3">Timestamp / ID</th>
              <th className="py-3 px-3">Host & User</th>
              <th className="py-3 px-3">Pattern / Finding</th>
              <th className="py-3 px-3">Category</th>
              <th className="py-3 px-3">Severity</th>
              <th className="py-3 px-3 text-center">Confidence</th>
              <th className="py-3 px-3">Advisory Action</th>
              <th className="py-3 px-3 text-right">Details</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {currentPageResults.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-8 text-center text-slate-500">
                  No detection findings match the selected filters.
                </td>
              </tr>
            ) : (
              currentPageResults.map((result) => {
                return (
                  <tr
                    key={result.id}
                    className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                    onClick={() => onSelectResult(result)}
                  >
                    <td className="py-3 px-3 text-slate-400">
                      <div className="font-semibold text-slate-300">
                        {result.timestamp.includes('T') ? result.timestamp.replace('T', ' ').substring(0, 19) : result.timestamp}
                      </div>
                      <div className="text-[10px] text-slate-500 font-mono">
                        {result.id.length > 22 ? result.id.substring(0, 20) + '..' : result.id}
                      </div>
                    </td>

                    <td className="py-3 px-3">
                      <div className="font-bold text-slate-200">
                        {result.host}
                      </div>
                      <div className="text-[11px] text-emerald-400 font-mono">
                        {result.username}
                        {result.sourceIp && (
                          <span className="text-slate-500 ml-1">({result.sourceIp})</span>
                        )}
                      </div>
                    </td>

                    <td className="py-3 px-3 max-w-xs">
                      <div className="font-bold text-white font-sans truncate">
                        {result.detection}
                      </div>
                      <div className="text-[11px] text-slate-400 truncate">
                        {result.securityFinding}
                      </div>
                    </td>

                    <td className="py-3 px-3">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          result.classification === 'THREAT'
                            ? 'bg-rose-950/80 text-rose-300 border border-rose-800'
                            : result.classification === 'SUSPICIOUS'
                            ? 'bg-amber-950/80 text-amber-300 border border-amber-800'
                            : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
                        }`}
                      >
                        {result.classification === 'THREAT' ? (
                          <ShieldAlert className="w-3 h-3 text-rose-400" />
                        ) : (
                          <AlertTriangle className="w-3 h-3 text-amber-400" />
                        )}
                        {result.classification}
                      </span>
                    </td>

                    <td className="py-3 px-3">
                      <SeverityBadge severity={result.severity} />
                    </td>

                    <td className="py-3 px-3 text-center">
                      <span className="font-bold text-slate-200">
                        {(result.confidence * 100).toFixed(0)}%
                      </span>
                    </td>

                    <td className="py-3 px-3 max-w-xs text-[11px] text-slate-400 font-sans truncate">
                      {result.recommendedAction}
                    </td>

                    <td className="py-3 px-3 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectResult(result);
                        }}
                        className="inline-flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 text-xs font-mono transition-colors"
                      >
                        <span>Inspect</span>
                        <ExternalLink className="w-3 h-3" />
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
        <div className="flex items-center justify-between pt-2 text-xs font-mono text-slate-400">
          <div>
            Showing {(page - 1) * pageSize + 1} to {Math.min(page * pageSize, filteredResults.length)} of {filteredResults.length} detections
          </div>
          <div className="flex items-center gap-2">
            <button
              disabled={page === 1}
              onClick={() => setPage(p => Math.max(1, p - 1))}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300"
            >
              Previous
            </button>
            <span>
              Page {page} of {totalPages}
            </span>
            <button
              disabled={page === totalPages}
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed text-slate-300"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
