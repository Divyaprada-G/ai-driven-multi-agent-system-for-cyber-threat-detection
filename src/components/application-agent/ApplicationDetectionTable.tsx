import React, { useState, useMemo } from 'react';
import {
  Search,
  Download,
  Filter,
  Eye,
  ShieldAlert,
  AlertTriangle,
  CheckCircle2,
  ChevronLeft,
  ChevronRight,
  Globe
} from 'lucide-react';
import { ApplicationAgentResult } from '../../types/application';
import { SeverityLevel } from '../../types';

interface Props {
  results: ApplicationAgentResult[];
  onSelectResult: (result: ApplicationAgentResult) => void;
}

export const ApplicationDetectionTable: React.FC<Props> = ({ results, onSelectResult }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [classificationFilter, setClassificationFilter] = useState<string>('ALL');
  const [threatTypeFilter, setThreatTypeFilter] = useState<string>('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  const filteredResults = useMemo(() => {
    return results.filter(res => {
      // Search term
      if (searchTerm) {
        const query = searchTerm.toLowerCase();
        const match =
          res.detection.toLowerCase().includes(query) ||
          (res.endpoint && res.endpoint.toLowerCase().includes(query)) ||
          (res.sourceIp && res.sourceIp.toLowerCase().includes(query)) ||
          (res.username && res.username.toLowerCase().includes(query)) ||
          res.observedActivity.toLowerCase().includes(query);
        if (!match) return false;
      }

      // Severity
      if (severityFilter !== 'ALL' && res.severity !== severityFilter) {
        return false;
      }

      // Classification
      if (classificationFilter !== 'ALL' && res.classification !== classificationFilter) {
        return false;
      }

      // Threat Type
      if (threatTypeFilter !== 'ALL' && res.threatType !== threatTypeFilter) {
        return false;
      }

      return true;
    });
  }, [results, searchTerm, severityFilter, classificationFilter, threatTypeFilter]);

  const totalPages = Math.ceil(filteredResults.length / itemsPerPage) || 1;
  const paginatedResults = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filteredResults.slice(start, start + itemsPerPage);
  }, [filteredResults, currentPage]);

  const handleExportJson = () => {
    const dataStr = JSON.stringify(filteredResults, null, 2);
    const blob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `application-security-findings-${new Date().toISOString().slice(0, 19)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300 border-rose-300 dark:border-rose-800';
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-950/60 dark:text-orange-300 border-orange-300 dark:border-orange-800';
      case 'MEDIUM':
        return 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 border-amber-300 dark:border-amber-800';
      default:
        return 'bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300 border-blue-300 dark:border-blue-800';
    }
  };

  const getStatusBadge = (code?: number) => {
    if (!code) return 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300';
    if (code >= 200 && code < 300) return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300';
    if (code === 401 || code === 403) return 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300';
    if (code >= 400 && code < 500) return 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300';
    return 'bg-red-100 text-red-800 dark:bg-red-950/60 dark:text-red-300';
  };

  const getClassificationBadge = (classification: string) => {
    switch (classification) {
      case 'THREAT':
        return 'bg-rose-100 dark:bg-rose-950/50 text-rose-700 dark:text-rose-300 border-rose-200 dark:border-rose-900';
      case 'SUSPICIOUS':
        return 'bg-amber-100 dark:bg-amber-950/50 text-amber-700 dark:text-amber-300 border-amber-200 dark:border-amber-900';
      default:
        return 'bg-emerald-100 dark:bg-emerald-950/50 text-emerald-700 dark:text-emerald-300 border-emerald-200 dark:border-emerald-900';
    }
  };

  return (
    <div id="application-detection-table-container" className="space-y-4">
      {/* Controls Bar */}
      <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm">
        {/* Search */}
        <div className="relative flex-1 min-w-[240px]">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            id="app-detection-search-input"
            type="text"
            placeholder="Search by endpoint, IP, user, signature or payload..."
            value={searchTerm}
            onChange={e => {
              setSearchTerm(e.target.value);
              setCurrentPage(1);
            }}
            className="w-full pl-9 pr-3 py-2 text-xs rounded-lg border border-slate-200 dark:border-slate-750 bg-slate-50 dark:bg-slate-800 text-slate-900 dark:text-slate-100 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
          />
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 text-xs text-slate-500 dark:text-slate-400">
            <Filter className="w-3.5 h-3.5" />
            <span className="font-semibold">Filter:</span>
          </div>

          <select
            id="app-severity-filter"
            value={severityFilter}
            onChange={e => {
              setSeverityFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="px-2.5 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-750 bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus:outline-none"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            id="app-classification-filter"
            value={classificationFilter}
            onChange={e => {
              setClassificationFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="px-2.5 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-750 bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus:outline-none"
          >
            <option value="ALL">All Classifications</option>
            <option value="THREAT">Threats Only</option>
            <option value="SUSPICIOUS">Suspicious Only</option>
            <option value="BENIGN">Benign Only</option>
          </select>

          <select
            id="app-threat-type-filter"
            value={threatTypeFilter}
            onChange={e => {
              setThreatTypeFilter(e.target.value);
              setCurrentPage(1);
            }}
            className="px-2.5 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-750 bg-slate-50 dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus:outline-none"
          >
            <option value="ALL">All Categories</option>
            <option value="WEB_ATTACK_INDICATOR">Web Attack Indicators</option>
            <option value="SUSPICIOUS_AUTH_PATTERN">Authentication Abuse</option>
            <option value="UNAUTHORIZED_ACCESS">Unauthorized Access</option>
            <option value="API_MISUSE">API Misuse</option>
            <option value="ABNORMAL_WEB_REQUEST">Endpoint Fuzzing / Scan</option>
            <option value="APPLICATION_ANOMALY">Server Error Anomalies</option>
            <option value="ABNORMAL_USER_BEHAVIOR">Abnormal User Behavior</option>
            <option value="NONE">Benign Requests</option>
          </select>

          <button
            id="export-app-findings-json-btn"
            onClick={handleExportJson}
            className="px-3 py-1.5 text-xs font-semibold rounded-lg bg-indigo-50 dark:bg-indigo-950/60 text-indigo-600 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-900 flex items-center gap-1.5 hover:bg-indigo-100 dark:hover:bg-indigo-900/80 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            Export JSON ({filteredResults.length})
          </button>
        </div>
      </div>

      {/* Table Card */}
      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table id="app-detection-data-table" className="w-full text-left text-xs">
            <thead className="bg-slate-50 dark:bg-slate-800/60 text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 font-semibold">
              <tr>
                <th className="py-3 px-4">Timestamp</th>
                <th className="py-3 px-3">Method & Code</th>
                <th className="py-3 px-4">Endpoint</th>
                <th className="py-3 px-3">Source IP</th>
                <th className="py-3 px-3">User</th>
                <th className="py-3 px-4">Security Finding</th>
                <th className="py-3 px-3">Severity</th>
                <th className="py-3 px-3">Conf.</th>
                <th className="py-3 px-3">Classification</th>
                <th className="py-3 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800 text-slate-700 dark:text-slate-300 font-mono">
              {paginatedResults.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-8 text-center text-slate-400 dark:text-slate-500 font-sans">
                    No matching application detections found for current filter criteria.
                  </td>
                </tr>
              ) : (
                paginatedResults.map(res => (
                  <tr
                    key={res.id}
                    id={`app-row-${res.id}`}
                    className="hover:bg-slate-50/70 dark:hover:bg-slate-800/40 transition-colors cursor-pointer"
                    onClick={() => onSelectResult(res)}
                  >
                    <td className="py-3 px-4 whitespace-nowrap text-slate-500 dark:text-slate-400 text-[11px]">
                      {res.timestamp}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${getStatusBadge(res.statusCode)}`}>
                        {res.method || 'REQ'} {res.statusCode || ''}
                      </span>
                    </td>
                    <td className="py-3 px-4 max-w-[200px] truncate text-slate-900 dark:text-slate-100 font-semibold" title={res.endpoint}>
                      {res.endpoint || '/'}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap text-slate-600 dark:text-slate-400">
                      {res.sourceIp || '-'}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap text-slate-600 dark:text-slate-400">
                      {res.username || '-'}
                    </td>
                    <td className="py-3 px-4 max-w-[280px] truncate font-sans text-slate-900 dark:text-slate-100 font-medium" title={res.detection}>
                      {res.detection}
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getSeverityBadge(res.severity)}`}>
                        {res.severity}
                      </span>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap text-[11px] font-semibold">
                      {Math.round(res.confidence * 100)}%
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold border ${getClassificationBadge(res.classification)}`}>
                        {res.classification}
                      </span>
                    </td>
                    <td className="py-3 px-3 whitespace-nowrap text-right">
                      <button
                        id={`inspect-app-btn-${res.id}`}
                        onClick={e => {
                          e.stopPropagation();
                          onSelectResult(res);
                        }}
                        className="px-2.5 py-1 text-xs font-sans font-semibold rounded bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 hover:bg-indigo-50 hover:text-indigo-600 dark:hover:bg-indigo-950 dark:hover:text-indigo-400 transition-colors inline-flex items-center gap-1"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="px-4 py-3 border-t border-slate-200 dark:border-slate-800 flex items-center justify-between text-xs text-slate-500 dark:text-slate-400 bg-slate-50/50 dark:bg-slate-900">
          <div>
            Showing <span className="font-semibold text-slate-800 dark:text-slate-200">{filteredResults.length === 0 ? 0 : (currentPage - 1) * itemsPerPage + 1}</span> to{' '}
            <span className="font-semibold text-slate-800 dark:text-slate-200">
              {Math.min(currentPage * itemsPerPage, filteredResults.length)}
            </span>{' '}
            of <span className="font-semibold text-slate-800 dark:text-slate-200">{filteredResults.length}</span> events
          </div>
          <div className="flex items-center gap-2">
            <button
              id="app-prev-page-btn"
              disabled={currentPage === 1}
              onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
              className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-750 disabled:opacity-40 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span className="font-semibold">
              Page {currentPage} of {totalPages}
            </span>
            <button
              id="app-next-page-btn"
              disabled={currentPage === totalPages}
              onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
              className="p-1.5 rounded-lg border border-slate-200 dark:border-slate-750 disabled:opacity-40 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
