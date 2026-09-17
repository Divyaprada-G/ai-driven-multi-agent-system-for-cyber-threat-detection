import React, { useState, useEffect } from 'react';
import {
  FileSpreadsheet,
  Download,
  FileText,
  Calendar,
  Filter,
  Printer,
  Copy,
  CheckCircle2,
  RefreshCw,
  ShieldCheck,
  Flame,
  AlertTriangle,
  Layers,
  Database
} from 'lucide-react';
import { reportService, StructuredSecurityReport } from '../../../services/reportService';
import { TimeRangeFilter } from '../../../types/analytics';
import { incidentManager } from '../../../services/alertIncident/incidentManager';

export const ReportsSection: React.FC = () => {
  const [timeRange, setTimeRange] = useState<TimeRangeFilter>('ALL');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [report, setReport] = useState<StructuredSecurityReport | null>(null);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  useEffect(() => {
    handleGenerateReport();
  }, [timeRange]);

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    try {
      const data = await reportService.generateComprehensiveReport(timeRange);
      setReport(data);
    } catch (err) {
      console.error('Failed to generate security summary report:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleExportIncidents = async (format: 'CSV' | 'JSON') => {
    setExportNotice(`Exporting incident records as ${format}...`);
    try {
      // Filter incidents if severityFilter !== 'ALL'
      const allIncidents = incidentManager.getIncidents();
      const filtered = severityFilter === 'ALL'
        ? allIncidents
        : allIncidents.filter(i => i.severity === severityFilter);

      const filename = `soc_incidents_${timeRange.toLowerCase()}_${severityFilter.toLowerCase()}`;

      if (format === 'JSON') {
        reportService.exportJSON(filtered, filename);
      } else {
        const rows = filtered.map(i => ({
          incidentId: i.id || i.incidentId,
          title: i.title,
          severity: i.severity,
          status: i.status,
          riskScore: i.riskScore || 85,
          priority: i.priority || 'P2',
          detectedAt: i.detectedAt || i.createdAt,
          host: i.affectedEntities?.join('; ') || 'workstation-fin-04',
          evidenceCount: i.evidence?.length || 0,
          assignedTo: i.assignedTo || 'Unassigned'
        }));
        reportService.exportCSV(rows, filename);
      }

      setExportNotice(`Successfully exported ${filtered.length} incident records as ${format}.`);
      setTimeout(() => setExportNotice(null), 3500);
    } catch (err: any) {
      setExportNotice(`Export failed: ${err.message}`);
      setTimeout(() => setExportNotice(null), 4000);
    }
  };

  const handleCopySummary = () => {
    if (!report) return;
    const text = `
=== CYBERSECURITY EXECUTIVE SECURITY SUMMARY ===
Report ID: ${report.reportId}
Generated At: ${report.generatedAt}
Time Range: ${report.dateRangeLabel}

EXECUTIVE SUMMARY:
${report.executiveSummary}

TELEMETRY TOTALS:
- Total Events Ingested: ${report.eventSummary.totalEvents}
- Critical Threats: ${report.threatSummary.criticalThreats}
- High Threats: ${report.threatSummary.highThreats}
- Open Incidents: ${report.incidentSummary.openIncidents}
- Resolved Incidents: ${report.incidentSummary.resolvedIncidents}

RECOMMENDED ACTIONS:
${report.recommendedActions.map(a => `- ${a}`).join('\n')}
    `.trim();

    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2500);
  };

  return (
    <div className="space-y-6 font-mono" id="dashboard-section-reports">
      {/* Top Banner & Export Actions */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xl">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2.5 h-2.5 rounded-full bg-indigo-400 animate-pulse" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
              <FileSpreadsheet className="w-4 h-4 text-indigo-400" />
              Security Reports & Incident Export Dossier
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-950/80 text-indigo-300 border border-indigo-700">
              Audit Ready
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Export structured incident records in CSV/JSON formats and generate formal executive security summaries.
          </p>
        </div>

        {/* Action Buttons for Export */}
        <div className="flex items-center gap-2 flex-wrap">
          <button
            id="btn-export-incidents-csv"
            onClick={() => handleExportIncidents('CSV')}
            className="px-3.5 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold transition-all shadow flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>

          <button
            id="btn-export-incidents-json"
            onClick={() => handleExportIncidents('JSON')}
            className="px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold transition-all shadow flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>

          <button
            onClick={() => window.print()}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs transition-colors flex items-center gap-1.5"
            title="Print or Save as PDF"
          >
            <Printer className="w-3.5 h-3.5 text-slate-400" />
            <span className="hidden sm:inline">Print</span>
          </button>
        </div>
      </div>

      {/* Export Feedback Notice */}
      {exportNotice && (
        <div className="p-3 bg-slate-950 border border-emerald-500/50 rounded-xl text-xs text-emerald-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          <span>{exportNotice}</span>
        </div>
      )}

      {/* Filters Bar: Date Range & Severity Filters */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-3 flex-wrap">
          {/* Date Range Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-xs font-semibold flex items-center gap-1">
              <Calendar className="w-3.5 h-3.5 text-indigo-400" />
              Date Range:
            </span>
            <div className="flex items-center gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
              {(['24H', '7D', '30D', 'ALL'] as TimeRangeFilter[]).map(r => (
                <button
                  key={r}
                  onClick={() => setTimeRange(r)}
                  className={`px-2.5 py-1 rounded text-xs font-bold transition-colors ${
                    timeRange === r
                      ? 'bg-indigo-600 text-white'
                      : 'text-slate-400 hover:text-white'
                  }`}
                >
                  {r === '24H' ? '24 Hours' : r === '7D' ? '7 Days' : r === '30D' ? '30 Days' : 'All Time'}
                </button>
              ))}
            </div>
          </div>

          {/* Severity Filter */}
          <div className="flex items-center gap-1.5">
            <span className="text-slate-400 text-xs font-semibold flex items-center gap-1">
              <Filter className="w-3.5 h-3.5 text-cyan-400" />
              Severity Scope:
            </span>
            <select
              value={severityFilter}
              onChange={e => setSeverityFilter(e.target.value)}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-slate-200 text-xs font-mono focus:outline-none focus:border-indigo-500"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical Only</option>
              <option value="HIGH">High Severity</option>
              <option value="MEDIUM">Medium Severity</option>
            </select>
          </div>
        </div>

        <button
          onClick={handleGenerateReport}
          disabled={isGenerating}
          className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs flex items-center gap-1.5"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin text-indigo-400' : ''}`} />
          <span>Regenerate Summary</span>
        </button>
      </div>

      {/* Generated Security Summary Document Card */}
      {report && (
        <div className="p-6 rounded-xl bg-slate-900 border border-slate-800 shadow-xl space-y-6">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-4">
            <div>
              <span className="text-[10px] text-cyan-400 uppercase tracking-widest font-semibold block">
                SOC DEFENSIVE INTELLIGENCE DOSSIER
              </span>
              <h3 className="text-base font-bold text-white mt-1">
                {report.title}
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Report ID: <span className="text-slate-300 font-bold">{report.reportId}</span> · Filter: {report.dateRangeLabel} · Generated: {report.generatedAt}
              </p>
            </div>

            <button
              onClick={handleCopySummary}
              className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-xs flex items-center gap-1.5 self-start sm:self-center"
            >
              <Copy className="w-3 h-3 text-cyan-400" />
              <span>{copied ? 'Copied to Clipboard!' : 'Copy Summary'}</span>
            </button>
          </div>

          {/* Executive Summary */}
          <div>
            <h4 className="text-xs font-bold text-white uppercase tracking-wider mb-2">
              Executive Security Summary
            </h4>
            <div className="p-4 bg-slate-950 rounded-xl border border-slate-800 text-xs text-slate-300 leading-relaxed space-y-2">
              <p>{report.executiveSummary}</p>
            </div>
          </div>

          {/* Structured Telemetry Metrics Summary */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Total Telemetry</span>
              <span className="text-lg font-bold text-white mt-1 block">
                {report.eventSummary.totalEvents.toLocaleString()}
              </span>
              <span className="text-[10px] text-slate-400 mt-0.5 block">
                Net: {report.eventSummary.networkEvents} · Sys: {report.eventSummary.systemEvents}
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Threat Detections</span>
              <span className="text-lg font-bold text-rose-400 mt-1 block">
                {report.threatSummary.totalThreats}
              </span>
              <span className="text-[10px] text-slate-400 mt-0.5 block">
                {report.threatSummary.criticalThreats} Critical · {report.threatSummary.highThreats} High
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Open Incidents</span>
              <span className="text-lg font-bold text-amber-400 mt-1 block">
                {report.incidentSummary.openIncidents}
              </span>
              <span className="text-[10px] text-slate-400 mt-0.5 block">
                Resolved: {report.incidentSummary.resolvedIncidents}
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Mean Risk Score</span>
              <span className="text-lg font-bold text-indigo-400 mt-1 block">
                {report.riskSummary.averageRiskScore}/100
              </span>
              <span className="text-[10px] text-slate-400 mt-0.5 block">
                Peak: {report.riskSummary.highestRiskScore}/100
              </span>
            </div>
          </div>

          {/* Recommended Security Actions */}
          <div>
            <h4 className="text-xs font-bold text-white uppercase tracking-wider mb-2">
              Recommended Defensive Containment Actions
            </h4>
            <div className="space-y-1.5">
              {report.recommendedActions.map((act, i) => (
                <div key={i} className="p-2.5 bg-slate-950 border border-slate-800 rounded-lg text-xs text-slate-300 flex items-start gap-2">
                  <span className="text-emerald-400 mt-0.5">✔</span>
                  <span>{act}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Disclaimers & Integrity Note */}
          <div className="p-3 bg-slate-950 rounded-lg border border-slate-800/80 text-[11px] text-slate-400">
            <span className="text-slate-300 font-bold">Academic Verification Note: </span>
            {report.limitationsAndDemoStatus}
          </div>
        </div>
      )}
    </div>
  );
};
