/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 8: Top Priority Threats Table with Filtering, Sorting & Status Management
 */

import React, { useState, useMemo } from 'react';
import {
  ShieldAlert,
  Search,
  Filter,
  ArrowUpDown,
  ExternalLink,
  ChevronRight,
  Flame,
  AlertTriangle,
  ShieldCheck,
  Activity,
  Check,
  Sparkles
} from 'lucide-react';
import { RiskAssessment, PriorityLevel, RiskStatus, RiskBand } from '../../types/riskScoring';
import { SeverityLevel, AgentType } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';

interface TopPriorityThreatsTableProps {
  assessments: RiskAssessment[];
  onSelectAssessment: (assessment: RiskAssessment) => void;
  onUpdateStatus?: (id: string, newStatus: RiskStatus) => void;
}

export const TopPriorityThreatsTable: React.FC<TopPriorityThreatsTableProps> = ({
  assessments,
  onSelectAssessment,
  onUpdateStatus
}) => {
  // Filter States
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [priorityFilter, setPriorityFilter] = useState<string>('ALL');
  const [riskBandFilter, setRiskBandFilter] = useState<string>('ALL');
  const [agentFilter, setAgentFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  // Sorting State
  const [sortField, setSortField] = useState<'RISK_DESC' | 'PRIORITY_ASC' | 'NEWEST' | 'OLDEST'>('PRIORITY_ASC');

  // Filtered and sorted data
  const processedData = useMemo(() => {
    return assessments
      .filter(item => {
        // Search filter
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchId = item.id.toLowerCase().includes(q);
          const matchType = String(item.threatClassification).toLowerCase().includes(q);
          const matchAction = item.recommendedAction.toLowerCase().includes(q);
          const matchSource = item.affectedSource.toLowerCase().includes(q);
          if (!matchId && !matchType && !matchAction && !matchSource) return false;
        }

        // Severity filter
        if (severityFilter !== 'ALL' && item.severity !== severityFilter) return false;

        // Priority filter
        if (priorityFilter !== 'ALL' && item.priority !== priorityFilter) return false;

        // Risk Band filter
        if (riskBandFilter !== 'ALL' && item.riskBand !== riskBandFilter) return false;

        // Agent filter
        if (agentFilter !== 'ALL') {
          if (!item.participatingAgents.includes(agentFilter as AgentType)) return false;
        }

        // Status filter
        if (statusFilter !== 'ALL' && item.status !== statusFilter) return false;

        return true;
      })
      .sort((a, b) => {
        if (sortField === 'RISK_DESC') {
          return b.riskScore - a.riskScore;
        }
        if (sortField === 'PRIORITY_ASC') {
          const priorityOrder: Record<PriorityLevel, number> = { P1: 1, P2: 2, P3: 3, P4: 4 };
          if (priorityOrder[a.priority] !== priorityOrder[b.priority]) {
            return priorityOrder[a.priority] - priorityOrder[b.priority];
          }
          return b.riskScore - a.riskScore;
        }
        if (sortField === 'NEWEST') {
          return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
        }
        if (sortField === 'OLDEST') {
          return new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime();
        }
        return 0;
      });
  }, [
    assessments,
    searchQuery,
    severityFilter,
    priorityFilter,
    riskBandFilter,
    agentFilter,
    statusFilter,
    sortField
  ]);

  const getPriorityBadge = (priority: PriorityLevel) => {
    switch (priority) {
      case 'P1':
        return (
          <span className="px-2 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800 text-[10px] font-mono font-bold flex items-center gap-1">
            <Flame className="w-3 h-3 text-rose-400 animate-pulse" /> P1 CRITICAL
          </span>
        );
      case 'P2':
        return (
          <span className="px-2 py-0.5 rounded bg-orange-950 text-orange-300 border border-orange-800 text-[10px] font-mono font-bold flex items-center gap-1">
            <ShieldAlert className="w-3 h-3 text-orange-400" /> P2 HIGH
          </span>
        );
      case 'P3':
        return (
          <span className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 text-[10px] font-mono font-bold flex items-center gap-1">
            <AlertTriangle className="w-3 h-3 text-amber-400" /> P3 MEDIUM
          </span>
        );
      case 'P4':
      default:
        return (
          <span className="px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 text-[10px] font-mono font-bold flex items-center gap-1">
            <ShieldCheck className="w-3 h-3 text-blue-400" /> P4 LOW
          </span>
        );
    }
  };

  const getStatusBadge = (status: RiskStatus) => {
    switch (status) {
      case 'NEW':
        return 'bg-cyan-950 text-cyan-300 border-cyan-800';
      case 'REVIEWING':
        return 'bg-purple-950 text-purple-300 border-purple-800';
      case 'ACKNOWLEDGED':
        return 'bg-amber-950 text-amber-300 border-amber-800';
      case 'RESOLVED':
        return 'bg-emerald-950 text-emerald-300 border-emerald-800';
      case 'FALSE_POSITIVE':
        return 'bg-slate-800 text-slate-400 border-slate-700';
      default:
        return 'bg-slate-900 text-slate-300 border-slate-800';
    }
  };

  return (
    <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden space-y-3" id="table-prioritized-threats">
      {/* Table Header & Controls */}
      <div className="p-4 border-b border-slate-800 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400" />
              Prioritized Threat Queue
            </h3>
            <p className="text-xs text-slate-400">
              Deterministic multi-factor risk scores synthesized from ML detection and correlation.
            </p>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Sort:</span>
            <select
              value={sortField}
              onChange={e => setSortField(e.target.value as any)}
              className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-200"
            >
              <option value="PRIORITY_ASC">Highest Priority (P1 → P4)</option>
              <option value="RISK_DESC">Highest Risk Score (100 → 0)</option>
              <option value="NEWEST">Newest Ingestion</option>
              <option value="OLDEST">Oldest Ingestion</option>
            </select>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-6 gap-2 text-xs font-mono">
          {/* Search Box */}
          <div className="sm:col-span-2 relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search ID, threat class, host..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 bg-slate-950 border border-slate-800 rounded text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500"
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={e => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-slate-300"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Priority Filter */}
          <select
            value={priorityFilter}
            onChange={e => setPriorityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-slate-300"
          >
            <option value="ALL">All Priorities</option>
            <option value="P1">P1 - Critical</option>
            <option value="P2">P2 - High</option>
            <option value="P3">P3 - Medium</option>
            <option value="P4">P4 - Low</option>
          </select>

          {/* Agent Filter */}
          <select
            value={agentFilter}
            onChange={e => setAgentFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-slate-300"
          >
            <option value="ALL">All Agents</option>
            <option value="NETWORK_AGENT">Network Agent</option>
            <option value="SYSTEM_AGENT">System Agent</option>
            <option value="APPLICATION_AGENT">Application Agent</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={e => setStatusFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 rounded px-2 py-1.5 text-slate-300"
          >
            <option value="ALL">All Statuses</option>
            <option value="NEW">New</option>
            <option value="REVIEWING">Reviewing</option>
            <option value="ACKNOWLEDGED">Acknowledged</option>
            <option value="RESOLVED">Resolved</option>
            <option value="FALSE_POSITIVE">False Positive</option>
          </select>
        </div>
      </div>

      {/* Table Body */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono text-slate-300">
          <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider text-[10px] border-b border-slate-800">
            <tr>
              <th className="py-2.5 px-3">Priority</th>
              <th className="py-2.5 px-3">Risk Score</th>
              <th className="py-2.5 px-3">Severity</th>
              <th className="py-2.5 px-3">Threat Classification</th>
              <th className="py-2.5 px-3">ML Conf.</th>
              <th className="py-2.5 px-3">Correlation</th>
              <th className="py-2.5 px-3">Timestamp</th>
              <th className="py-2.5 px-3">Status</th>
              <th className="py-2.5 px-3 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {processedData.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-8 text-center text-slate-500">
                  No risk assessments match the selected filter criteria.
                </td>
              </tr>
            ) : (
              processedData.map(item => (
                <tr
                  key={item.id}
                  id={`row-risk-${item.id.toLowerCase()}`}
                  className="hover:bg-slate-800/40 transition-colors group cursor-pointer"
                  onClick={() => onSelectAssessment(item)}
                >
                  {/* Priority */}
                  <td className="py-3 px-3">
                    {getPriorityBadge(item.priority)}
                  </td>

                  {/* Risk Score */}
                  <td className="py-3 px-3">
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-sm font-bold ${
                          item.riskScore >= 81
                            ? 'text-rose-400'
                            : item.riskScore >= 61
                            ? 'text-orange-400'
                            : item.riskScore >= 31
                            ? 'text-amber-400'
                            : 'text-blue-400'
                        }`}
                      >
                        {item.riskScore}
                        <span className="text-[10px] text-slate-500 font-normal">/100</span>
                      </span>

                      {/* Small visual bar */}
                      <div className="w-12 h-1.5 bg-slate-800 rounded-full overflow-hidden hidden sm:block">
                        <div
                          className={`h-full ${
                            item.riskScore >= 81
                              ? 'bg-rose-500'
                              : item.riskScore >= 61
                              ? 'bg-orange-500'
                              : item.riskScore >= 31
                              ? 'bg-amber-500'
                              : 'bg-blue-500'
                          }`}
                          style={{ width: `${item.riskScore}%` }}
                        />
                      </div>
                    </div>
                  </td>

                  {/* Severity */}
                  <td className="py-3 px-3">
                    <SeverityBadge severity={item.severity} />
                  </td>

                  {/* Threat Classification & Target */}
                  <td className="py-3 px-3">
                    <div className="font-bold text-white text-xs max-w-[220px] truncate">
                      {String(item.threatClassification)}
                    </div>
                    <div className="text-[10px] text-slate-400 truncate max-w-[200px]">
                      {item.affectedSource}
                    </div>
                  </td>

                  {/* ML Confidence */}
                  <td className="py-3 px-3">
                    <span className="text-emerald-400 font-bold">{item.confidence}%</span>
                  </td>

                  {/* Correlation */}
                  <td className="py-3 px-3">
                    <div className="text-cyan-400 font-bold text-[11px] truncate max-w-[130px]">
                      {item.correlationId}
                    </div>
                    <div className="text-[10px] text-slate-500">
                      {item.participatingAgents.length} agent(s)
                    </div>
                  </td>

                  {/* Timestamp */}
                  <td className="py-3 px-3 text-slate-400 text-[11px]">
                    {item.timestamp.includes('T')
                      ? item.timestamp.split('T')[1].substring(0, 8)
                      : item.timestamp.split(' ')[1] || item.timestamp}
                  </td>

                  {/* Status Dropdown */}
                  <td className="py-3 px-3" onClick={e => e.stopPropagation()}>
                    <select
                      value={item.status}
                      onChange={e =>
                        onUpdateStatus && onUpdateStatus(item.id, e.target.value as RiskStatus)
                      }
                      className={`text-[10px] font-mono px-2 py-1 rounded border font-bold ${getStatusBadge(
                        item.status
                      )}`}
                    >
                      <option value="NEW">NEW</option>
                      <option value="REVIEWING">REVIEWING</option>
                      <option value="ACKNOWLEDGED">ACKNOWLEDGED</option>
                      <option value="RESOLVED">RESOLVED</option>
                      <option value="FALSE_POSITIVE">FALSE POSITIVE</option>
                    </select>
                  </td>

                  {/* Action */}
                  <td className="py-3 px-3 text-right">
                    <button
                      onClick={e => {
                        e.stopPropagation();
                        onSelectAssessment(item);
                      }}
                      className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-950 text-cyan-400 hover:text-cyan-300 border border-slate-700 hover:border-cyan-700 transition-colors text-[10px] inline-flex items-center gap-1"
                    >
                      <span>Explain</span>
                      <ChevronRight className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Footer Info */}
      <div className="p-3 border-t border-slate-800 flex items-center justify-between text-[11px] font-mono text-slate-500">
        <span>Showing {processedData.length} of {assessments.length} prioritized assessments</span>
        <span className="text-cyan-400/80">Click any row to inspect explainable factors</span>
      </div>
    </div>
  );
};
