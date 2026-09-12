import React, { useState } from 'react';
import { FileSpreadsheet, Download, RefreshCw, FileText, CheckCircle2, ShieldCheck, Activity } from 'lucide-react';
import { reportService, SecurityReportData } from '../services/reportService';
import { INITIAL_METRICS, INITIAL_AGENTS, INITIAL_INCIDENTS, INITIAL_RISK_ASSESSMENTS } from '../services/mockData';

export const ReportsPage: React.FC = () => {
  const [report, setReport] = useState<SecurityReportData | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    try {
      const data = await reportService.generateSummaryReport();
      setReport(data);
    } finally {
      setIsGenerating(false);
    }
  };

  const handleExportCSV = () => {
    const records = INITIAL_INCIDENTS.map(i => ({
      incidentId: i.incidentId,
      threatType: i.threatType,
      severity: i.severity,
      riskScore: i.riskScore,
      affectedSource: i.affectedSource,
      status: i.status,
      assignedTo: i.assignedTo,
      detectedAt: i.detectedAt
    }));
    reportService.exportCSV(records);
  };

  const handleExportJSON = () => {
    const exportBundle = {
      project: 'AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION',
      version: '1.0',
      exportedAt: new Date().toISOString(),
      metrics: INITIAL_METRICS,
      agents: INITIAL_AGENTS,
      incidents: INITIAL_INCIDENTS,
      risks: INITIAL_RISK_ASSESSMENTS
    };
    reportService.exportJSON(exportBundle);
  };

  return (
    <div className="space-y-6" id="page-reports">
      {/* Header & Export Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest">
              Audit & Compliance Briefings
            </span>
          </div>
          <h2 className="text-xl font-bold text-white tracking-tight">
            Security Intelligence Reports
          </h2>
          <p className="text-xs text-slate-400 mt-1 max-w-2xl">
            Generate executive intelligence briefings, multi-agent operational telemetry audits, and regulatory compliance snapshots.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
          <button
            id="btn-generate-report"
            onClick={handleGenerateReport}
            disabled={isGenerating}
            className="px-3.5 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 text-white font-semibold transition-colors inline-flex items-center gap-1.5 shadow-sm"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isGenerating ? 'animate-spin' : ''}`} />
            <span>{isGenerating ? 'Synthesizing...' : 'Generate Report'}</span>
          </button>

          <button
            id="btn-export-csv"
            onClick={handleExportCSV}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors inline-flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export CSV</span>
          </button>

          <button
            id="btn-export-json"
            onClick={handleExportJSON}
            className="px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors inline-flex items-center gap-1.5"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* 15. REPORTS SECTIONS */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Security Summary Card */}
        <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
          <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-cyan-400" />
            1. Security Summary
          </h3>
          <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 text-xs text-slate-300 space-y-2 font-mono">
            <div className="flex justify-between">
              <span className="text-slate-500">Overall Threat Posture:</span>
              <span className="text-amber-400 font-bold">ELEVATED (LEVEL 3)</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Ingested Log Events:</span>
              <span className="text-slate-100 font-bold">{INITIAL_METRICS.totalEvents.toLocaleString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Correlation Efficiency:</span>
              <span className="text-emerald-400 font-bold">98.4% without false cascade</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Active High-Priority Kill Chains:</span>
              <span className="text-rose-400 font-bold">1 In Progress (Finance Subnet)</span>
            </div>
          </div>
        </div>

        {/* Threat Statistics Card */}
        <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
          <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            2. Threat Statistics
          </h3>
          <div className="grid grid-cols-2 gap-2 text-xs font-mono">
            <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Critical Threats</span>
              <span className="text-lg font-bold text-rose-400">16</span>
            </div>
            <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800">
              <span className="text-slate-500 block text-[10px]">High Severity</span>
              <span className="text-lg font-bold text-orange-400">86</span>
            </div>
            <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Medium Severity</span>
              <span className="text-lg font-bold text-amber-400">284</span>
            </div>
            <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800">
              <span className="text-slate-500 block text-[10px]">Low / Informational</span>
              <span className="text-lg font-bold text-blue-400">1,042</span>
            </div>
          </div>
        </div>
      </div>

      {/* Agent Performance & Incident Summary */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Agent Performance */}
        <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
          <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            3. Agent Performance
          </h3>
          <div className="space-y-2 font-mono text-xs">
            {INITIAL_AGENTS.map(agent => (
              <div key={agent.agentId} className="p-2.5 bg-slate-950/80 rounded-lg border border-slate-800 flex justify-between items-center">
                <div>
                  <span className="text-slate-200 font-bold">{agent.name}</span>
                  <div className="text-[10px] text-slate-500">{agent.eventsProcessed.toLocaleString()} events analyzed</div>
                </div>
                <div className="text-right">
                  <span className="text-emerald-400 font-bold">{agent.detectionConfidence}%</span>
                  <div className="text-[10px] text-slate-400">Uptime: {agent.uptime}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Incident Summary & Risk Distribution */}
        <div className="p-5 bg-slate-900/70 border border-slate-800 rounded-xl space-y-3">
          <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            <FileText className="w-4 h-4 text-purple-400" />
            4. Incident Summary & Risk Distribution
          </h3>
          <div className="p-3 bg-slate-950/80 rounded-lg border border-slate-800 space-y-2 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-500">Unresolved P0 Incidents:</span>
              <span className="text-rose-400 font-bold">1 Active</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Contained Incidents:</span>
              <span className="text-indigo-400 font-bold">1 Contained</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Resolved Today:</span>
              <span className="text-emerald-400 font-bold">1 Resolved</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Average Triage Time:</span>
              <span className="text-slate-300 font-bold">4.2 minutes</span>
            </div>
          </div>
        </div>
      </div>

      {/* Generated Report Preview (if generated) */}
      {report && (
        <div className="p-6 bg-slate-950 border border-cyan-500/40 rounded-xl space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div>
              <span className="text-xs font-mono text-cyan-400">DOCUMENT ID: {report.reportId}</span>
              <h3 className="text-base font-bold text-white tracking-tight mt-0.5">
                {report.scope}
              </h3>
            </div>
            <span className="text-xs font-mono text-slate-500">
              Generated: {new Date(report.generatedAt).toLocaleString()}
            </span>
          </div>

          <div className="space-y-3 text-xs">
            <h4 className="font-mono text-slate-400 uppercase tracking-wider">
              Strategic Security Recommendations:
            </h4>
            <div className="space-y-1.5 font-mono">
              {report.recommendations.map((rec, idx) => (
                <div key={idx} className="p-2.5 bg-slate-900/80 rounded border border-slate-800 text-slate-300 flex items-start gap-2">
                  <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
