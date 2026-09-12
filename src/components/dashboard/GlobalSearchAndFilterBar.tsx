/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Global Search & Advanced Filtering Component
 *
 * Implements Sections 18 & 19 of Prompt 10:
 * - Real-time search across Events, Threats, Risks, Alerts, Incidents
 * - Reusable filter controls (Time Range, Severity, Risk Level, Priority, Threat Classification, Agent, Status)
 * - Purely client-side state filtering without altering underlying telemetry
 */

import React, { useState } from 'react';
import {
  Search,
  Filter,
  X,
  RotateCcw,
  SlidersHorizontal,
  ChevronDown,
  ChevronUp,
  Clock,
  ShieldAlert,
  AlertTriangle,
  Flame,
  Layers,
  Activity
} from 'lucide-react';
import { GlobalFilterCriteria, TimeRangeFilter } from '../../types/analytics';
import { SeverityLevel, AgentType } from '../../types';
import { ThreatClass } from '../../types/threatDetection';
import { PriorityLevel } from '../../types/riskScoring';
import { AlertLifecycleStatus, IncidentLifecycleStatus } from '../../types/alertIncident';

interface GlobalSearchAndFilterBarProps {
  filters: GlobalFilterCriteria;
  onFilterChange: (newFilters: GlobalFilterCriteria) => void;
  resultCount?: number;
  totalCount?: number;
}

export const GlobalSearchAndFilterBar: React.FC<GlobalSearchAndFilterBarProps> = ({
  filters,
  onFilterChange,
  resultCount,
  totalCount
}) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    onFilterChange({ ...filters, searchTerm: e.target.value });
  };

  const handleTimeRangeChange = (range: TimeRangeFilter) => {
    onFilterChange({ ...filters, timeRange: range });
  };

  const handleSeverityChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({
      ...filters,
      severity: e.target.value as 'ALL' | SeverityLevel
    });
  };

  const handlePriorityChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({
      ...filters,
      priority: e.target.value as 'ALL' | PriorityLevel
    });
  };

  const handleClassificationChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({
      ...filters,
      threatClassification: e.target.value as 'ALL' | ThreatClass
    });
  };

  const handleAgentChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({
      ...filters,
      agent: e.target.value as 'ALL' | AgentType
    });
  };

  const handleAlertStatusChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    onFilterChange({
      ...filters,
      alertStatus: e.target.value as 'ALL' | AlertLifecycleStatus
    });
  };

  const handleReset = () => {
    onFilterChange({
      searchTerm: '',
      timeRange: 'ALL',
      severity: 'ALL',
      riskLevel: 'ALL',
      priority: 'ALL',
      threatClassification: 'ALL',
      agent: 'ALL',
      alertStatus: 'ALL',
      incidentStatus: 'ALL'
    });
  };

  const hasActiveFilters =
    Boolean(filters.searchTerm) ||
    filters.timeRange !== 'ALL' ||
    (filters.severity && filters.severity !== 'ALL') ||
    (filters.priority && filters.priority !== 'ALL') ||
    (filters.threatClassification && filters.threatClassification !== 'ALL') ||
    (filters.agent && filters.agent !== 'ALL') ||
    (filters.alertStatus && filters.alertStatus !== 'ALL');

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 sm:p-4 shadow-lg space-y-3">
      {/* Primary Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
          <input
            id="global-soc-search-input"
            type="text"
            placeholder="Search Events, Threats, Risks, Alerts, Incidents (by ID, Title, IP, MITRE Technique)..."
            value={filters.searchTerm || ''}
            onChange={handleSearchChange}
            className="w-full pl-10 pr-10 py-2.5 bg-slate-950 border border-slate-700/80 rounded-lg text-xs font-mono text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
          />
          {filters.searchTerm && (
            <button
              onClick={() => onFilterChange({ ...filters, searchTerm: '' })}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white p-1"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          )}
        </div>

        {/* Quick Time Range Pills */}
        <div className="flex items-center gap-1.5 bg-slate-950 p-1 border border-slate-800 rounded-lg">
          {(['24H', '7D', '30D', 'ALL'] as TimeRangeFilter[]).map(range => (
            <button
              key={range}
              onClick={() => handleTimeRangeChange(range)}
              className={`px-2.5 py-1 text-[11px] font-mono font-medium rounded transition-colors ${
                filters.timeRange === range
                  ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
              }`}
            >
              {range === 'ALL' ? 'All Data' : range}
            </button>
          ))}
        </div>

        {/* Toggle Filters Button */}
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs font-mono border transition-colors ${
            hasActiveFilters
              ? 'bg-indigo-950/60 border-indigo-700 text-indigo-300'
              : 'bg-slate-800/60 border-slate-700 text-slate-300 hover:bg-slate-800'
          }`}
        >
          <SlidersHorizontal className="w-3.5 h-3.5" />
          <span>Filters</span>
          {hasActiveFilters && (
            <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          )}
          {isExpanded ? (
            <ChevronUp className="w-3.5 h-3.5 ml-1" />
          ) : (
            <ChevronDown className="w-3.5 h-3.5 ml-1" />
          )}
        </button>

        {hasActiveFilters && (
          <button
            onClick={handleReset}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono text-slate-400 hover:text-rose-300 hover:bg-rose-950/40 border border-slate-800 transition-colors"
            title="Reset all filters"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Reset</span>
          </button>
        )}
      </div>

      {/* Expanded Filter Controls */}
      {isExpanded && (
        <div className="pt-3 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 animate-in fade-in duration-150 text-xs font-mono">
          {/* Severity */}
          <div>
            <label className="block text-[10px] uppercase text-slate-400 mb-1">Severity</label>
            <select
              value={filters.severity || 'ALL'}
              onChange={handleSeverityChange}
              className="w-full py-1.5 px-2 bg-slate-950 border border-slate-700 rounded text-xs text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Priority */}
          <div>
            <label className="block text-[10px] uppercase text-slate-400 mb-1">Priority</label>
            <select
              value={filters.priority || 'ALL'}
              onChange={handlePriorityChange}
              className="w-full py-1.5 px-2 bg-slate-950 border border-slate-700 rounded text-xs text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Priorities</option>
              <option value="P1">P1 - Immediate</option>
              <option value="P2">P2 - Urgent</option>
              <option value="P3">P3 - Elevated</option>
              <option value="P4">P4 - Routine</option>
            </select>
          </div>

          {/* Classification */}
          <div>
            <label className="block text-[10px] uppercase text-slate-400 mb-1">Threat Class</label>
            <select
              value={filters.threatClassification || 'ALL'}
              onChange={handleClassificationChange}
              className="w-full py-1.5 px-2 bg-slate-950 border border-slate-700 rounded text-xs text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Threat Classes</option>
              <option value="MULTI_STAGE_THREAT">Multi-Stage Threat</option>
              <option value="AUTHENTICATION_THREAT">Authentication Threat</option>
              <option value="PRIVILEGE_ESCALATION">Privilege Escalation</option>
              <option value="WEB_THREAT">Web Exploit</option>
              <option value="NETWORK_THREAT">Network Threat</option>
              <option value="API_THREAT">API Threat</option>
              <option value="ANOMALY">Anomaly</option>
              <option value="SUSPICIOUS">Suspicious</option>
              <option value="BENIGN">Benign</option>
            </select>
          </div>

          {/* Specialized Agent */}
          <div>
            <label className="block text-[10px] uppercase text-slate-400 mb-1">Agent Layer</label>
            <select
              value={filters.agent || 'ALL'}
              onChange={handleAgentChange}
              className="w-full py-1.5 px-2 bg-slate-950 border border-slate-700 rounded text-xs text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Agents</option>
              <option value="NETWORK_AGENT">Network Agent</option>
              <option value="SYSTEM_AGENT">System Agent</option>
              <option value="APPLICATION_AGENT">Application Agent</option>
            </select>
          </div>

          {/* Alert Status */}
          <div>
            <label className="block text-[10px] uppercase text-slate-400 mb-1">Alert Status</label>
            <select
              value={filters.alertStatus || 'ALL'}
              onChange={handleAlertStatusChange}
              className="w-full py-1.5 px-2 bg-slate-950 border border-slate-700 rounded text-xs text-white focus:outline-none focus:border-cyan-500"
            >
              <option value="ALL">All Alert Statuses</option>
              <option value="NEW">New (Unassigned)</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="INVESTIGATING">Investigating</option>
              <option value="RESOLVED">Resolved</option>
              <option value="FALSE_POSITIVE">False Positive</option>
            </select>
          </div>

          {/* Active Filter Metrics */}
          <div className="flex flex-col justify-end">
            <span className="text-[10px] text-slate-500 uppercase block mb-1">Matching Records</span>
            <div className="py-1.5 px-2 bg-slate-950/80 border border-slate-800 rounded text-cyan-400 font-bold flex items-center justify-between">
              <span>{resultCount !== undefined ? resultCount : '-'}</span>
              <span className="text-[10px] text-slate-500 font-normal">
                of {totalCount !== undefined ? totalCount : '-'}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
