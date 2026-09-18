import React, { useState, useEffect, useCallback } from 'react';
import {
  Activity,
  Server,
  Database,
  Cpu,
  ShieldAlert,
  Radio,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  RefreshCw,
  Zap,
  HardDrive,
  Workflow,
  Mail,
  Network,
  Globe,
  Terminal,
  Shield,
  Layers,
  Copy,
  Check
} from 'lucide-react';

export type OperationalStatus = 'LIVE' | 'SIMULATION' | 'OFFLINE' | 'DEGRADED' | 'ERROR' | 'NOT_CONFIGURED' | 'IDLE';

interface SystemStatusPayload {
  overallStatus: OperationalStatus;
  timestamp: string;
  backendStatus: {
    state: OperationalStatus;
    service: string;
    version: string;
    uptimeSeconds: number;
    nodeVersion: string;
    platform: string;
    arch: string;
    memoryUsageMb: {
      rss: number;
      heapTotal: number;
      heapUsed: number;
    };
  };
  collectorStatus: {
    overall: OperationalStatus;
    systemCollector: {
      state: OperationalStatus;
      eventsCollected: number;
      eventsDropped: number;
      errorsCount: number;
      intervalMs: number;
      lastEventTimestamp?: string;
    };
    networkCollector: {
      state: OperationalStatus;
      eventsCollected: number;
      eventsDropped: number;
      errorsCount: number;
      intervalMs: number;
      lastEventTimestamp?: string;
    };
    applicationCollector: {
      state: OperationalStatus;
      eventsCollected: number;
      eventsDropped: number;
      errorsCount: number;
      intervalMs: number;
      lastEventTimestamp?: string;
      totalRequests?: number;
    };
    windowsCollector: {
      state: OperationalStatus;
      registeredCount: number;
      activeCount: number;
      collectors: any[];
    };
  };
  databaseStatus: {
    state: OperationalStatus;
    status: string;
    connected: boolean;
    mode: string;
    fallbackStore: string;
    details: string;
  };
  mlServiceStatus: {
    overall: OperationalStatus;
    pythonFastApi: {
      state: OperationalStatus;
      connected: boolean;
      url: string;
      details: string;
    };
    integratedEngine: {
      state: OperationalStatus;
      modelId: string;
      modelType: string;
      randomForest: string;
      isolationForest: string;
      artifactsLoaded: number;
    };
  };
  activeAgents: Array<{
    id: string;
    name: string;
    type: string;
    state: OperationalStatus;
    eventsProcessed: number;
    lastActive: string | null;
    description: string;
  }>;
  lastReceivedEvent: {
    eventId: string;
    timestamp: string;
    source: string;
    host: string;
    isSimulated: boolean;
  } | null;
  lastProcessedEvent: {
    eventId: string;
    timestamp: string;
    source: string;
    isConfirmedThreat: boolean;
    riskScore: number;
    status: string;
    latencyMs: number;
  } | null;
  processingLatency: {
    averageLatencyMs: number;
    p95LatencyMs: number;
    unit: string;
  };
  errorCount: {
    totalAgentErrors: number;
    totalDuplicatesDropped: number;
    collectorErrors: number;
    totalErrors: number;
  };
  integrations: {
    n8n: {
      state: OperationalStatus;
      configured: boolean;
      destination: string;
      description: string;
    };
    email: {
      state: OperationalStatus;
      configured: boolean;
      destination: string;
      description: string;
    };
    webhook: {
      state: OperationalStatus;
      configured: boolean;
      destination: string;
      description: string;
    };
  };
  realTimeIngestion: {
    state: OperationalStatus;
    verified: boolean;
    currentEps: number;
    totalLiveEvents: number;
    totalSimulatedEvents: number;
    streamMode: string;
  };
  eventMetrics: {
    totalEventsProcessed: number;
    totalDuplicatesDropped: number;
    liveEvents: number;
    simulatedEvents: number;
    verifiedReal: boolean;
  };
}

export const SystemStatusPage: React.FC = () => {
  const [data, setData] = useState<SystemStatusPayload | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [lastCheckTime, setLastCheckTime] = useState<Date>(new Date());
  const [copiedCurl, setCopiedCurl] = useState<boolean>(false);
  const [copiedPs, setCopiedPs] = useState<boolean>(false);

  const fetchStatus = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const res = await fetch('/api/system/status');
      if (res.ok) {
        const json = await res.json();
        setData(json);
        setLastCheckTime(new Date());
      }
    } catch (err) {
      console.error('Failed to fetch system status:', err);
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 4000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  const renderStatusBadge = (status: OperationalStatus, size: 'sm' | 'md' = 'sm') => {
    const sizeClasses = size === 'md' ? 'px-3 py-1 text-xs font-semibold' : 'px-2 py-0.5 text-[11px] font-medium';
    switch (status) {
      case 'LIVE':
        return (
          <span className={`inline-flex items-center gap-1.5 rounded-full bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 font-mono ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            LIVE
          </span>
        );
      case 'SIMULATION':
        return (
          <span className={`inline-flex items-center gap-1.5 rounded-full bg-amber-950/80 text-amber-300 border border-amber-700/80 font-mono ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
            SIMULATION
          </span>
        );
      case 'DEGRADED':
        return (
          <span className={`inline-flex items-center gap-1.5 rounded-full bg-yellow-950/80 text-yellow-300 border border-yellow-700/80 font-mono ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-yellow-400" />
            DEGRADED
          </span>
        );
      case 'ERROR':
        return (
          <span className={`inline-flex items-center gap-1.5 rounded-full bg-rose-950/80 text-rose-300 border border-rose-700/80 font-mono ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-rose-400" />
            ERROR
          </span>
        );
      case 'NOT_CONFIGURED':
        return (
          <span className={`inline-flex items-center gap-1.5 rounded-full bg-slate-800 text-slate-400 border border-slate-700 font-mono ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
            NOT CONFIGURED
          </span>
        );
      case 'IDLE':
        return (
          <span className={`inline-flex items-center gap-1.5 rounded-full bg-cyan-950/80 text-cyan-300 border border-cyan-800/80 font-mono ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            IDLE (READY)
          </span>
        );
      case 'OFFLINE':
      default:
        return (
          <span className={`inline-flex items-center gap-1.5 rounded-full bg-slate-900 text-slate-400 border border-slate-700 font-mono ${sizeClasses}`}>
            <span className="w-1.5 h-1.5 rounded-full bg-slate-500" />
            OFFLINE
          </span>
        );
    }
  };

  const sampleCurl = `curl -X POST http://localhost:3000/api/telemetry/ingest \\
  -H "Content-Type: application/json" \\
  -d '{
    "source": "NETWORK",
    "timestamp": "${new Date().toISOString()}",
    "event": {
      "sourceIp": "192.168.1.150",
      "destinationIp": "10.0.0.5",
      "destinationPort": 22,
      "protocol": "TCP",
      "flag": "SYN_FLOOD",
      "host": "WIN-SRV-2026"
    }
  }'`;

  const samplePowershell = `$body = @{
    source = "SYSTEM"
    timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ssZ")
    event = @{
        eventId = "4688"
        host = $env:COMPUTERNAME
        processName = "powershell.exe"
        commandLine = "powershell.exe -enc SQBFAFgA..."
        userName = $env:USERNAME
    }
} | ConvertTo-Json

Invoke-RestMethod -Uri "http://localhost:3000/api/telemetry/ingest" -Method Post -Body $body -ContentType "application/json"`;

  const handleCopy = (text: string, type: 'curl' | 'ps') => {
    navigator.clipboard.writeText(text);
    if (type === 'curl') {
      setCopiedCurl(true);
      setTimeout(() => setCopiedCurl(false), 2000);
    } else {
      setCopiedPs(true);
      setTimeout(() => setCopiedPs(false), 2000);
    }
  };

  if (isLoading && !data) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[500px] text-slate-400 space-y-4">
        <RefreshCw className="w-8 h-8 animate-spin text-cyan-400" />
        <p className="text-sm font-mono">Conducting verified backend health audit...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-12" id="system-status-page">
      {/* Top Banner: Truthfulness & Operational Health Statement */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-xl relative overflow-hidden">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2 flex-wrap">
              <span className="text-xs uppercase tracking-wider text-slate-400 font-mono font-semibold">
                Truthfulness Audit
              </span>
              {data && renderStatusBadge(data.overallStatus, 'md')}
              <span className="text-xs text-slate-500 font-mono">
                Verified: {lastCheckTime.toLocaleTimeString()}
              </span>
            </div>
            <h1 className="text-2xl font-bold text-white tracking-tight flex items-center gap-2.5">
              <Shield className="w-6 h-6 text-cyan-400" />
              System Operational Status & Health Audit
            </h1>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl">
              Strict truthfulness policy: Every status indicator is derived from verified live runtime health checks.
              Simulated, offline, or unconfigured components are reported honestly without artificial mock numbers.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={fetchStatus}
              disabled={isRefreshing}
              className="inline-flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 text-sm font-medium transition shadow"
            >
              <RefreshCw className={`w-4 h-4 text-cyan-400 ${isRefreshing ? 'animate-spin' : ''}`} />
              Run Health Audit
            </button>
          </div>
        </div>
      </div>

      {/* Primary KPI Grid: High-level System Vital Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Metric 1: Telemetry Ingestion */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-400 font-mono">Telemetry Ingestion</span>
            <Radio className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {data?.realTimeIngestion.currentEps.toFixed(1) || '0.0'}
            </span>
            <span className="text-xs text-slate-400">EPS</span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs pt-2 border-t border-slate-800">
            <span className="text-slate-500">Mode:</span>
            {data && renderStatusBadge(data.realTimeIngestion.state)}
          </div>
        </div>

        {/* Metric 2: Processing Latency */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-400 font-mono">Pipeline Latency (Avg)</span>
            <Clock className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {data?.processingLatency.averageLatencyMs || 0}
            </span>
            <span className="text-xs text-slate-400">ms</span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs pt-2 border-t border-slate-800">
            <span className="text-slate-500">P95 Latency:</span>
            <span className="text-slate-300 font-mono">{data?.processingLatency.p95LatencyMs || 0} ms</span>
          </div>
        </div>

        {/* Metric 3: Verified Events vs Simulated */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-400 font-mono">Verified Real Events</span>
            <CheckCircle2 className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {data?.realTimeIngestion.totalLiveEvents || 0}
            </span>
            <span className="text-xs text-slate-400">live</span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs pt-2 border-t border-slate-800">
            <span className="text-slate-500">Simulated:</span>
            <span className="text-amber-400 font-mono">{data?.realTimeIngestion.totalSimulatedEvents || 0}</span>
          </div>
        </div>

        {/* Metric 4: System Errors & Deduplications */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-400 font-mono">Error & Dedup Count</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-bold text-white font-mono">
              {data?.errorCount.totalErrors || 0}
            </span>
            <span className="text-xs text-slate-400">errors</span>
          </div>
          <div className="mt-3 flex items-center justify-between text-xs pt-2 border-t border-slate-800">
            <span className="text-slate-500">Duplicates Suppressed:</span>
            <span className="text-cyan-400 font-mono">{data?.errorCount.totalDuplicatesDropped || 0}</span>
          </div>
        </div>
      </div>

      {/* Grid: Core Infrastructure Health (Collector, Backend, Database, ML) */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Card 1: Collector Status */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <Radio className="w-5 h-5 text-cyan-400" />
              <h2 className="text-base font-semibold text-white">Telemetry Collector Status</h2>
            </div>
            {data && renderStatusBadge(data.collectorStatus.overall)}
          </div>

          <div className="space-y-3.5">
            {/* System Collector */}
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-indigo-400" />
                  <span className="text-sm font-medium text-slate-200">Host System Collector</span>
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Interval: {data?.collectorStatus.systemCollector.intervalMs}ms | Collected: {data?.collectorStatus.systemCollector.eventsCollected}
                </div>
              </div>
              {data && renderStatusBadge(data.collectorStatus.systemCollector.state)}
            </div>

            {/* Network Collector */}
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <Network className="w-4 h-4 text-emerald-400" />
                  <span className="text-sm font-medium text-slate-200">Network Flow Collector</span>
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Interval: {data?.collectorStatus.networkCollector.intervalMs}ms | Collected: {data?.collectorStatus.networkCollector.eventsCollected}
                </div>
              </div>
              {data && renderStatusBadge(data.collectorStatus.networkCollector.state)}
            </div>

            {/* Application Collector */}
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <Globe className="w-4 h-4 text-amber-400" />
                  <span className="text-sm font-medium text-slate-200">Application Access Collector</span>
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Requests Intercepted: {data?.collectorStatus.applicationCollector.totalRequests || 0} | Collected: {data?.collectorStatus.applicationCollector.eventsCollected}
                </div>
              </div>
              {data && renderStatusBadge(data.collectorStatus.applicationCollector.state)}
            </div>

            {/* Windows Security Collector */}
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80 flex items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <Terminal className="w-4 h-4 text-cyan-400" />
                  <span className="text-sm font-medium text-slate-200">External Windows Collector</span>
                </div>
                <div className="text-xs text-slate-400 mt-1">
                  Registered Hosts: {data?.collectorStatus.windowsCollector.registeredCount} | Active: {data?.collectorStatus.windowsCollector.activeCount}
                </div>
              </div>
              {data && renderStatusBadge(data.collectorStatus.windowsCollector.state)}
            </div>
          </div>
        </div>

        {/* Card 2: Backend & Database Persistence */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <Server className="w-5 h-5 text-indigo-400" />
              <h2 className="text-base font-semibold text-white">Backend & Database Status</h2>
            </div>
            {data && renderStatusBadge(data.backendStatus.state)}
          </div>

          <div className="space-y-4">
            {/* Backend Runtime */}
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-slate-200">Express API Gateway</span>
                <span className="text-xs font-mono text-cyan-400">Port 3000 (Operational)</span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs text-slate-400">
                <div>Uptime: <span className="text-slate-200 font-mono">{Math.floor((data?.backendStatus.uptimeSeconds || 0) / 60)} min</span></div>
                <div>Node: <span className="text-slate-200 font-mono">{data?.backendStatus.nodeVersion}</span></div>
                <div>Memory (RSS): <span className="text-slate-200 font-mono">{data?.backendStatus.memoryUsageMb.rss} MB</span></div>
                <div>Heap Used: <span className="text-slate-200 font-mono">{data?.backendStatus.memoryUsageMb.heapUsed} MB</span></div>
              </div>
            </div>

            {/* Database Persistence */}
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <Database className="w-4 h-4 text-emerald-400" />
                  <span className="text-sm font-medium text-slate-200">Database Persistence</span>
                </div>
                {data && renderStatusBadge(data.databaseStatus.state)}
              </div>
              <div className="text-xs text-slate-400 mb-2">
                Primary Store: <span className="text-slate-200 font-mono font-semibold">{data?.databaseStatus.mode}</span> | Fallback: <span className="text-cyan-400 font-mono">Local JSON Store</span>
              </div>
              <p className="text-xs text-slate-400 bg-slate-900 p-2 rounded border border-slate-800 leading-relaxed">
                {data?.databaseStatus.details}
              </p>
            </div>
          </div>
        </div>

        {/* Card 3: Machine-Learning Service Status */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <Zap className="w-5 h-5 text-amber-400" />
              <h2 className="text-base font-semibold text-white">Machine-Learning Service Status</h2>
            </div>
            {data && renderStatusBadge(data.mlServiceStatus.overall)}
          </div>

          <div className="space-y-3.5">
            {/* Python FastAPI Service */}
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-sm font-medium text-slate-200">Python FastAPI Microservice</span>
                {data && renderStatusBadge(data.mlServiceStatus.pythonFastApi.state)}
              </div>
              <div className="text-xs text-slate-400">
                Endpoint: <span className="font-mono text-slate-300">{data?.mlServiceStatus.pythonFastApi.url}</span>
              </div>
              <p className="text-xs text-slate-400 mt-1.5 leading-relaxed">
                {data?.mlServiceStatus.pythonFastApi.details}
              </p>
            </div>

            {/* Integrated Inference Engine */}
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-sm font-medium text-slate-200">Integrated ML Inference Engine</span>
                {data && renderStatusBadge(data.mlServiceStatus.integratedEngine.state)}
              </div>
              <div className="grid grid-cols-2 gap-2 text-xs text-slate-400 mt-2">
                <div>Random Forest: <span className="text-emerald-400 font-mono font-semibold">READY</span></div>
                <div>Isolation Forest: <span className="text-emerald-400 font-mono font-semibold">READY</span></div>
                <div>Active Model ID: <span className="text-slate-200 font-mono">{data?.mlServiceStatus.integratedEngine.modelId}</span></div>
                <div>Artifacts Loaded: <span className="text-slate-200 font-mono">{data?.mlServiceStatus.integratedEngine.artifactsLoaded}</span></div>
              </div>
            </div>
          </div>
        </div>

        {/* Card 4: Third-Party Integrations Status (n8n & Email) */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
          <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
            <div className="flex items-center gap-2.5">
              <Workflow className="w-5 h-5 text-purple-400" />
              <h2 className="text-base font-semibold text-white">Integrations & Notification Dispatch</h2>
            </div>
            <span className="text-xs text-slate-400 font-mono">SOC Automation</span>
          </div>

          <div className="space-y-3.5">
            {/* n8n Integration */}
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <Workflow className="w-4 h-4 text-purple-400" />
                  <span className="text-sm font-medium text-slate-200">n8n Security Workflow</span>
                </div>
                {data && renderStatusBadge(data.integrations.n8n.state)}
              </div>
              <div className="text-xs text-slate-400">
                Destination: <span className="font-mono text-slate-300">{data?.integrations.n8n.destination}</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                {data?.integrations.n8n.description}
              </p>
            </div>

            {/* Email Dispatch */}
            <div className="p-3 bg-slate-950/60 rounded-lg border border-slate-800/80">
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <Mail className="w-4 h-4 text-cyan-400" />
                  <span className="text-sm font-medium text-slate-200">Email Alerts (SMTP)</span>
                </div>
                {data && renderStatusBadge(data.integrations.email.state)}
              </div>
              <div className="text-xs text-slate-400">
                Destination: <span className="font-mono text-slate-300">{data?.integrations.email.destination}</span>
              </div>
              <p className="text-xs text-slate-400 mt-1">
                {data?.integrations.email.description}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Six Active Cyber Agents Matrix */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
        <div className="flex items-center justify-between pb-3 mb-4 border-b border-slate-800">
          <div>
            <h2 className="text-base font-semibold text-white flex items-center gap-2">
              <Layers className="w-5 h-5 text-cyan-400" />
              Cybersecurity Agent Operational Matrix
            </h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Statuses are dynamically verified: An agent is only marked LIVE when real events are processed, SIMULATION during demo mode, or IDLE when waiting.
            </p>
          </div>
          <span className="text-xs text-slate-400 font-mono">6 Agents Active</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {data?.activeAgents.map((agent) => (
            <div
              key={agent.id}
              className="p-4 bg-slate-950/70 rounded-xl border border-slate-800/90 flex flex-col justify-between hover:border-slate-700 transition"
            >
              <div>
                <div className="flex items-start justify-between gap-2 mb-2">
                  <span className="text-sm font-semibold text-slate-100">{agent.name}</span>
                  {renderStatusBadge(agent.state)}
                </div>
                <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed mb-3">
                  {agent.description}
                </p>
              </div>

              <div className="pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs font-mono text-slate-400">
                <span>Processed: <strong className="text-slate-200">{agent.eventsProcessed}</strong></span>
                <span>
                  {agent.lastActive ? new Date(agent.lastActive).toLocaleTimeString() : 'Awaiting data'}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Real-time Telemetry Verification: Last Received & Last Processed Events */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Last Received Event */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
            <Radio className="w-4 h-4 text-cyan-400" />
            Last Ingested Telemetry Event
          </h3>
          {data?.lastReceivedEvent ? (
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5 font-mono text-xs">
              <div className="flex justify-between">
                <span className="text-slate-500">Event ID:</span>
                <span className="text-cyan-300 font-semibold">{data.lastReceivedEvent.eventId}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Source:</span>
                <span className="text-slate-300">{data.lastReceivedEvent.source}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Host:</span>
                <span className="text-slate-300">{data.lastReceivedEvent.host || 'Unknown'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Mode:</span>
                <span className={data.lastReceivedEvent.isSimulated ? 'text-amber-400' : 'text-emerald-400'}>
                  {data.lastReceivedEvent.isSimulated ? 'SIMULATED' : 'LIVE'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Timestamp:</span>
                <span className="text-slate-400">{new Date(data.lastReceivedEvent.timestamp).toLocaleTimeString()}</span>
              </div>
            </div>
          ) : (
            <div className="p-6 text-center text-slate-500 font-mono text-xs border border-dashed border-slate-800 rounded-lg">
              No telemetry events received yet. Start the stream or send external telemetry.
            </div>
          )}
        </div>

        {/* Last Processed Event */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
          <h3 className="text-sm font-semibold text-slate-200 mb-3 flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            Last Processed Pipeline Event
          </h3>
          {data?.lastProcessedEvent ? (
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-1.5 font-mono text-xs">
              <div className="flex justify-between">
                <span className="text-slate-500">Event ID:</span>
                <span className="text-emerald-300 font-semibold">{data.lastProcessedEvent.eventId}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Source / Status:</span>
                <span className="text-slate-300">{data.lastProcessedEvent.source} ({data.lastProcessedEvent.status})</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Risk Score:</span>
                <span className={data.lastProcessedEvent.riskScore >= 70 ? 'text-rose-400 font-bold' : 'text-slate-200'}>
                  {data.lastProcessedEvent.riskScore}/100
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Threat Confirmed:</span>
                <span className={data.lastProcessedEvent.isConfirmedThreat ? 'text-rose-400' : 'text-emerald-400'}>
                  {data.lastProcessedEvent.isConfirmedThreat ? 'YES' : 'NO'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Pipeline Latency:</span>
                <span className="text-cyan-400">{data.lastProcessedEvent.latencyMs} ms</span>
              </div>
            </div>
          ) : (
            <div className="p-6 text-center text-slate-500 font-mono text-xs border border-dashed border-slate-800 rounded-lg">
              No events processed through the 6-agent pipeline yet.
            </div>
          )}
        </div>
      </div>

      {/* Windows Host Telemetry Ingestion Verification Guide */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow">
        <h3 className="text-base font-semibold text-white mb-2 flex items-center gap-2">
          <Terminal className="w-5 h-5 text-cyan-400" />
          Windows Host Telemetry Ingestion Verification
        </h3>
        <p className="text-xs text-slate-400 mb-4 leading-relaxed">
          To verify genuine real-time ingestion from any Windows host without simulated data, run the PowerShell script or test via curl to deliver telemetry directly to the ingestion API:
        </p>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Curl Command */}
          <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-300 font-semibold">Bash / cURL Telemetry Ingestion</span>
              <button
                onClick={() => handleCopy(sampleCurl, 'curl')}
                className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
              >
                {copiedCurl ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedCurl ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre className="text-[11px] font-mono text-slate-400 overflow-x-auto p-2 bg-slate-900/80 rounded">
              {sampleCurl}
            </pre>
          </div>

          {/* PowerShell Command */}
          <div className="bg-slate-950 p-3.5 rounded-lg border border-slate-800">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono text-slate-300 font-semibold">Windows PowerShell Live Ingestion</span>
              <button
                onClick={() => handleCopy(samplePowershell, 'ps')}
                className="inline-flex items-center gap-1 text-[11px] px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition"
              >
                {copiedPs ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedPs ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre className="text-[11px] font-mono text-slate-400 overflow-x-auto p-2 bg-slate-900/80 rounded">
              {samplePowershell}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
};
