/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Advanced Security Reporting & Multi-Entity Export Center
 *
 * Implements Sections 27-32 of Prompt 10:
 * - Structured Security Report generation from live SOC state
 * - Executive Summary with dynamic calculated figures
 * - Date-range filtering (24H, 7D, 30D, ALL)
 * - Multi-Entity Export (Alerts, Incidents, Risks, Threats, Events, Relational Bundle) in CSV & JSON
 * - Preserves relational IDs across all exported datasets
 */

import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  RefreshCw,
  CheckCircle2,
  ShieldCheck,
  Activity,
  Calendar,
  Layers,
  Flame,
  Bell,
  Printer,
  ChevronDown,
  Info,
  ShieldAlert,
  SlidersHorizontal
} from 'lucide-react';
import { reportService, StructuredSecurityReport } from '../services/reportService';
import { TimeRangeFilter } from '../types/analytics';
import { SeverityBadge } from '../components/common/SeverityBadge';

export const ReportsPage: React.FC = () => {
  const [report, setReport] = useState<StructuredSecurityReport | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [timeRange, setTimeRange] = useState<TimeRangeFilter>('ALL');
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const [exportNotice, setExportNotice] = useState<string | null>(null);

  useEffect(() => {
    // Generate initial report
    handleGenerateReport();
  }, [timeRange]);

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    try {
      const data = await reportService.generateComprehensiveReport(timeRange);
      setReport(data);
    } catch (err: any) {
      console.error('Failed to generate report:', err);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleExportEntity = async (
    entity: 'ALERTS' | 'INCIDENTS' | 'RISKS' | 'THREATS' | 'EVENTS' | 'ALL_RELATIONAL',
    format: 'CSV' | 'JSON'
  ) => {
    setExportMenuOpen(false);
    setExportNotice(`Exporting ${entity} as ${format}...`);
    try {
      await reportService.exportEntities(entity, format);
      setTimeout(() => setExportNotice(null), 3000);
    } catch (err: any) {
      setExportNotice(`Export failed: ${err.message}`);
      setTimeout(() => setExportNotice(null), 4000);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="space-y-6 font-mono" id="page-reports">
      {/* Header & Export Actions */}
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-cyan-400 uppercase tracking-widest font-semibold">
              Stage 10: Security Intelligence & Dossier Reporting
            </span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight mt-0.5">
            Security Intelligence & Audit Reporting
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Generate formal multi-agent threat intelligence briefs, executive summaries, and multi-entity telemetry exports.
          </p>
        </div>

        {/* Controls & Export Dropdown */}
        <div className="flex flex-wrap items-center gap-2 text-xs">
          {/* Time Range Filter (Section 30) */}
          <div className="flex items-center gap-1 bg-slate-900 border border-slate-800 p-1 rounded-lg">
            {(['24H', '7D', '30D', 'ALL'] as TimeRangeFilter[]).map(r => (
              <button
                key={r}
                onClick={() => setTimeRange(r)}
                className={`px-2.5 py-1 text-[11px] rounded transition-colors ${
                  timeRange === r
                    ? 'bg-cyan-500/20 text-cyan-300 font-bold border border-cyan-500/40'
                    : 'text-slate-400 hover:text-white'
                }`}
              >
                {r === 'ALL' ? 'All Data' : r}
              </button>
            ))}
          </div>

          <button
            id="btn-generate-report"
            onClick={handleGenerateReport}
            disabled={isGenerating}
            className="px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold transition-colors inline-flex items-center gap-1.5 shadow-sm"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin' : ''}`} />
            <span>{isGenerating ? 'Compiling...' : 'Re-Generate'}</span>
          </button>

          {/* Multi-Entity Export Dropdown (Sections 31 & 32) */}
          <div className="relative">
            <button
              onClick={() => setExportMenuOpen(!exportMenuOpen)}
              className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors inline-flex items-center gap-1.5 font-bold"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export Telemetry</span>
              <ChevronDown className="w-3 h-3 ml-1" />
            </button>

            {exportMenuOpen && (
              <div className="absolute right-0 mt-2 w-64 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl p-2 z-50 text-xs space-y-1 animate-in fade-in duration-150">
                <span className="text-[10px] text-slate-400 uppercase px-2 py-1 block font-bold">
                  Tabular CSV Exports:
                </span>
                <button
                  onClick={() => handleExportEntity('ALERTS', 'CSV')}
                  className="w-full text-left px-2.5 py-1.5 rounded hover:bg-slate-800 text-slate-300 flex justify-between"
                >
                  <span>Alerts Registry</span>
                  <span className="text-[10px] text-cyan-400 font-bold">.CSV</span>
                </button>
                <button
                  onClick={() => handleExportEntity('INCIDENTS', 'CSV')}
                  className="w-full text-left px-2.5 py-1.5 rounded hover:bg-slate-800 text-slate-300 flex justify-between"
                >
                  <span>Incident Dossiers</span>
                  <span className="text-[10px] text-purple-400 font-bold">.CSV</span>
                </button>
                <button
                  onClick={() => handleExportEntity('RISKS', 'CSV')}
                  className="w-full text-left px-2.5 py-1.5 rounded hover:bg-slate-800 text-slate-300 flex justify-between"
                >
                  <span>Risk Assessments</span>
                  <span className="text-[10px] text-orange-400 font-bold">.CSV</span>
                </button>
                <button
                  onClick={() => handleExportEntity('THREATS', 'CSV')}
                  className="w-full text-left px-2.5 py-1.5 rounded hover:bg-slate-800 text-slate-300 flex justify-between"
                >
                  <span>Threat Detections</span>
                  <span className="text-[10px] text-rose-400 font-bold">.CSV</span>
                </button>
                <button
                  onClick={() => handleExportEntity('EVENTS', 'CSV')}
                  className="w-full text-left px-2.5 py-1.5 rounded hover:bg-slate-800 text-slate-300 flex justify-between"
                >
                  <span>Security Events</span>
                  <span className="text-[10px] text-emerald-400 font-bold">.CSV</span>
                </button>

                <div className="pt-1 border-t border-slate-800">
                  <span className="text-[10px] text-slate-400 uppercase px-2 py-1 block font-bold">
                    Relational JSON Exports:
                  </span>
                  <button
                    onClick={() => handleExportEntity('ALL_RELATIONAL', 'JSON')}
                    className="w-full text-left px-2.5 py-1.5 rounded hover:bg-indigo-950/60 text-indigo-300 flex justify-between font-bold"
                  >
                    <span>Full Relational SOC Bundle</span>
                    <span className="text-[10px] text-indigo-400">.JSON</span>
                  </button>
                </div>
              </div>
            )}
          </div>

          <button
            onClick={handlePrint}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors inline-flex items-center gap-1.5"
            title="Print or Save as PDF"
          >
            <Printer className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Print / PDF</span>
          </button>
        </div>
      </div>

      {exportNotice && (
        <div className="p-3 bg-cyan-950/60 border border-cyan-700 rounded-lg text-xs text-cyan-300 flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{exportNotice}</span>
        </div>
      )}

      {/* Main Report Document (Sections 27-29) */}
      {report && (
        <div className="p-6 sm:p-8 bg-slate-950 border border-slate-800 rounded-xl shadow-2xl space-y-6 text-xs text-slate-300 print:bg-white print:text-black print:border-none">
          {/* Document Header */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-4 border-b border-slate-800 print:border-black gap-3">
            <div>
              <div className="flex items-center gap-2">
                <span className="text-cyan-400 print:text-blue-600 font-bold">{report.reportId}</span>
                <span className="px-2 py-0.5 rounded bg-slate-900 print:bg-slate-100 text-[10px] text-slate-400 font-bold border border-slate-800">
                  {report.dateRangeLabel}
                </span>
              </div>
              <h3 className="text-lg font-bold text-white print:text-black tracking-tight mt-1">
                {report.title}
              </h3>
            </div>
            <div className="text-right text-[11px] text-slate-400 print:text-slate-600">
              <div>Generated: <strong className="text-slate-200 print:text-black">{report.generatedAt}</strong></div>
              <div className="text-[10px] mt-0.5">Classification: RESTRICTED // SOC-OPERATIONS</div>
            </div>
          </div>

          {/* 1. Executive Summary (Section 28) */}
          <div className="space-y-2">
            <h4 className="text-xs uppercase font-bold text-cyan-400 print:text-blue-600 flex items-center gap-1.5">
              <ShieldCheck className="w-3.5 h-3.5" />
              1. Executive Summary
            </h4>
            <div className="p-4 bg-slate-900/80 print:bg-slate-50 border border-slate-800 print:border-slate-300 rounded-lg leading-relaxed text-slate-200 print:text-slate-800">
              {report.executiveSummary}
            </div>
          </div>

          {/* 2. Key Operational Metrics Summary Table */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
            <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Events Evaluated</span>
              <span className="text-lg font-bold text-white">{report.eventSummary.totalEvents.toLocaleString()}</span>
            </div>
            <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Confirmed Threats</span>
              <span className="text-lg font-bold text-indigo-400">{report.threatSummary.totalThreats}</span>
            </div>
            <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Average Risk Score</span>
              <span className="text-lg font-bold text-orange-400">{report.riskSummary.averageRiskScore}/100</span>
            </div>
            <div className="p-3 bg-slate-900/60 rounded-lg border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">False Positive Rate</span>
              <span className="text-lg font-bold text-cyan-400">{report.alertSummary.falsePositiveRate}</span>
            </div>
          </div>

          {/* 3. Multi-Agent Analysis & Findings */}
          <div className="space-y-2">
            <h4 className="text-xs uppercase font-bold text-cyan-400 print:text-blue-600 flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5" />
              2. Multi-Agent Activity & Domain Findings
            </h4>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border border-slate-800 print:border-slate-300">
                <thead className="bg-slate-900 print:bg-slate-100 text-slate-400 uppercase text-[10px]">
                  <tr>
                    <th className="py-2 px-3">Agent Layer</th>
                    <th className="py-2 px-3">Events Monitored</th>
                    <th className="py-2 px-3">Suspicious Findings</th>
                    <th className="py-2 px-3">Threat Contributions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {report.multiAgentAnalysis.map(agent => (
                    <tr key={agent.agent}>
                      <td className="py-2.5 px-3 font-bold text-white print:text-black">{agent.agent}</td>
                      <td className="py-2.5 px-3">{agent.events.toLocaleString()}</td>
                      <td className="py-2.5 px-3 text-cyan-400 font-bold">{agent.findings}</td>
                      <td className="py-2.5 px-3 text-rose-400 font-bold">{agent.threats}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* 4. Threat & Risk Distributions */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Threat Distribution */}
            <div className="space-y-2">
              <h4 className="text-xs uppercase font-bold text-cyan-400 print:text-blue-600">
                3. Threat Classification Breakdown
              </h4>
              <div className="space-y-1.5">
                {report.threatDistribution.map(t => (
                  <div
                    key={t.classification}
                    className="p-2 bg-slate-900/60 rounded border border-slate-800 flex justify-between text-xs"
                  >
                    <span className="text-slate-300">{t.classification}</span>
                    <span className="font-bold text-cyan-400">
                      {t.count} ({t.percentage}%)
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Risk Distribution */}
            <div className="space-y-2">
              <h4 className="text-xs uppercase font-bold text-cyan-400 print:text-blue-600">
                4. Risk Score Tier Distribution
              </h4>
              <div className="space-y-1.5">
                {report.riskDistribution.map(r => (
                  <div
                    key={r.level}
                    className="p-2 bg-slate-900/60 rounded border border-slate-800 flex justify-between text-xs"
                  >
                    <span className="text-slate-300">{r.level}</span>
                    <span className="font-bold text-orange-400">
                      {r.count} ({r.percentage}%)
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* 5. Recommended Strategic Actions */}
          <div className="space-y-2">
            <h4 className="text-xs uppercase font-bold text-cyan-400 print:text-blue-600 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              5. Recommended Security Actions
            </h4>
            <div className="space-y-1.5">
              {report.recommendedActions.map((action, idx) => (
                <div
                  key={idx}
                  className="p-2.5 bg-slate-900/60 print:bg-slate-50 rounded border border-slate-800 print:border-slate-300 flex items-start gap-2 text-xs"
                >
                  <span className="font-bold text-cyan-400 print:text-blue-600">{idx + 1}.</span>
                  <span className="text-slate-300 print:text-slate-800">{action}</span>
                </div>
              ))}
            </div>
          </div>

          {/* 6. Honest Limitations & Academic Status (Section 27) */}
          <div className="p-3.5 bg-slate-900 border border-slate-800 print:border-slate-400 rounded-lg flex items-start gap-2.5 text-xs text-slate-400">
            <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
            <p className="leading-relaxed">
              <strong className="text-white print:text-black">Runtime Limitations & Demonstration Status: </strong>
              {report.limitationsAndDemoStatus}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};
