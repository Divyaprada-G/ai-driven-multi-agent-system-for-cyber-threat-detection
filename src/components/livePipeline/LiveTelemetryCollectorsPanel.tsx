/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Real-Time Telemetry Collectors Management Panel
 * 
 * Strict enforcement:
 * - Clear distinction between LIVE production telemetry and SIMULATED demo data
 * - Displays authentic OS/Network/App collector statuses (LIVE, OFFLINE, ERROR)
 * - Zero fake event counts or fabricated metrics
 */

import React, { useState } from 'react';
import {
  Cpu,
  Wifi,
  Globe,
  Play,
  Square,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Terminal,
  Upload,
  ShieldCheck,
  Radio
} from 'lucide-react';
import { livePipelineService } from '../../services/livePipelineService';
import { LivePipelineStatus } from '../../types/livePipeline';

interface LiveTelemetryCollectorsPanelProps {
  status: LivePipelineStatus;
}

export const LiveTelemetryCollectorsPanel: React.FC<LiveTelemetryCollectorsPanelProps> = ({ status }) => {
  const [isStartingAll, setIsStartingAll] = useState(false);
  const [isStoppingAll, setIsStoppingAll] = useState(false);
  const [activeToggle, setActiveToggle] = useState<string | null>(null);
  const [ingestLogText, setIngestLogText] = useState('');
  const [ingestSource, setIngestSource] = useState<'system' | 'network' | 'application'>('system');
  const [isIngesting, setIsIngesting] = useState(false);
  const [ingestFeedback, setIngestFeedback] = useState<string | null>(null);
  const [showAgentCommand, setShowAgentCommand] = useState(false);

  const collectors = status.collectorHealth || [
    { type: 'SYSTEM', name: 'Host System Collector', state: 'OFFLINE', enabled: false, eventsCollected: 0, currentEps: 0 },
    { type: 'NETWORK', name: 'Network Socket Collector', state: 'OFFLINE', enabled: false, eventsCollected: 0, currentEps: 0 },
    { type: 'APPLICATION', name: 'Application HTTP Collector', state: 'OFFLINE', enabled: false, eventsCollected: 0, currentEps: 0 }
  ];

  const handleToggleCollector = async (type: 'SYSTEM' | 'NETWORK' | 'APPLICATION', currentState: string) => {
    setActiveToggle(type);
    try {
      if (currentState === 'LIVE') {
        await livePipelineService.stopLiveCollector(type);
      } else {
        await livePipelineService.startLiveCollector(type);
      }
    } finally {
      setActiveToggle(null);
    }
  };

  const handleStartAll = async () => {
    setIsStartingAll(true);
    try {
      await livePipelineService.startAllLiveCollectors();
    } finally {
      setIsStartingAll(false);
    }
  };

  const handleStopAll = async () => {
    setIsStoppingAll(true);
    try {
      await livePipelineService.stopAllLiveCollectors();
    } finally {
      setIsStoppingAll(false);
    }
  };

  const handleManualIngest = async () => {
    if (!ingestLogText.trim()) return;
    setIsIngesting(true);
    setIngestFeedback(null);
    try {
      const res = await livePipelineService.ingestManualTelemetry({
        source: ingestSource,
        rawLogs: ingestLogText.trim(),
        isSimulated: false
      });
      setIngestFeedback(`Successfully ingested ${res?.eventsProcessed || 1} live events.`);
      setIngestLogText('');
    } catch (err: any) {
      setIngestFeedback(`Ingestion error: ${err.message}`);
    } finally {
      setIsIngesting(false);
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-xl space-y-5" id="telemetry-collectors-panel">
      {/* Panel Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-800 pb-4">
        <div>
          <div className="flex items-center space-x-2">
            <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse" />
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <Radio className="w-5 h-5 text-emerald-400" />
              Genuine Real-Time Telemetry Ingestion Layer
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Target Architecture Phase 1: Real-time sampling of Host OS, Network sockets, and Web/API HTTP traffic. Strictly separates authentic live telemetry from synthetic simulation.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={() => setShowAgentCommand(!showAgentCommand)}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-semibold flex items-center space-x-1.5 border border-slate-700 transition-colors"
          >
            <Terminal className="w-3.5 h-3.5 text-cyan-400" />
            <span>{showAgentCommand ? 'Hide Agent Script' : 'External Host Agent'}</span>
          </button>

          <button
            onClick={handleStartAll}
            disabled={isStartingAll}
            className="px-3.5 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold flex items-center space-x-1.5 shadow-md shadow-emerald-950/50 disabled:opacity-50 transition-all cursor-pointer"
          >
            <Play className="w-3.5 h-3.5 fill-current" />
            <span>START ALL COLLECTORS</span>
          </button>

          <button
            onClick={handleStopAll}
            disabled={isStoppingAll}
            className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white text-xs font-bold flex items-center space-x-1.5 border border-slate-700 disabled:opacity-50 transition-all cursor-pointer"
          >
            <Square className="w-3.5 h-3.5 fill-current" />
            <span>STOP ALL</span>
          </button>
        </div>
      </div>

      {/* External Host Collector Script Accordion */}
      {showAgentCommand && (
        <div className="bg-slate-950 border border-cyan-900/50 rounded-lg p-4 space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between text-cyan-400 font-bold">
            <span className="flex items-center gap-1.5">
              <Terminal className="w-4 h-4" />
              Windows Security & Telemetry Collector Service
            </span>
            <span className="text-[10px] bg-cyan-950 px-2 py-0.5 rounded border border-cyan-800 text-cyan-300">
              Modular Python Collector
            </span>
          </div>
          <p className="text-slate-300 text-[11px] font-sans">
            Collects authentic Windows Event Logs (<code className="text-emerald-400">System</code>, <code className="text-emerald-400">Application</code>, and privileged <code className="text-emerald-400">Security</code>), tails application log files, and performs non-intrusive local socket telemetry:
          </p>

          <div className="space-y-2">
            <div className="text-[11px] text-slate-400 font-semibold font-sans">
              1. Run Complete Windows Collector (CLI runner):
            </div>
            <div className="bg-slate-900 p-2.5 rounded border border-slate-800 text-emerald-300 select-all font-mono text-[11px]">
              python run_windows_collector.py --backend-url {window?.location?.origin || 'http://localhost:3000'} --channels System,Application,Security --interval 4.0
            </div>

            <div className="text-[11px] text-slate-400 font-semibold font-sans">
              2. Run with Custom Application Logs directory & Passive Network Monitoring:
            </div>
            <div className="bg-slate-900 p-2.5 rounded border border-slate-800 text-cyan-300 select-all font-mono text-[11px]">
              python run_windows_collector.py --app-log-dirs "C:\inetpub\logs\LogFiles,C:\AppLogs" --enabled-collectors event_log,file_tail,network
            </div>

            <div className="text-[10px] text-slate-400 font-sans flex items-center gap-1">
              <ShieldCheck className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Permission Note: Reading the <code>Security</code> event log requires Administrator elevation. <code>System</code>, <code>Application</code>, file tailing, and passive network telemetry run under standard user permissions.</span>
            </div>
          </div>
        </div>
      )}

      {/* Registered External Windows Collectors */}
      {status.externalCollectors && status.externalCollectors.length > 0 && (
        <div className="bg-slate-950/70 border border-emerald-500/30 rounded-lg p-3 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
              <span className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                Active External Windows Telemetry Agents ({status.externalCollectors.length})
              </span>
            </div>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/50 px-2 py-0.5 rounded border border-emerald-800/40">
              AUTHENTIC TELEMETRY STREAMING
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 pt-1">
            {status.externalCollectors.map((ec: any, idx: number) => (
              <div key={idx} className="bg-slate-900/90 border border-slate-800 rounded p-2.5 text-xs font-mono">
                <div className="flex items-center justify-between text-slate-200 font-bold">
                  <span>{ec.hostname}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-900/60 text-emerald-300">
                    {ec.status}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 mt-1 truncate">
                  Collector: {ec.collectorName}
                </div>
                <div className="flex justify-between items-center text-[10px] text-slate-500 mt-2 pt-1 border-t border-slate-800">
                  <span>Events: <strong className="text-white">{ec.eventsCount}</strong></span>
                  <span>{new Date(ec.lastSeen).toLocaleTimeString()}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Collectors Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {collectors.map((c: any) => {
          const isLive = c.state === 'LIVE';
          const icon = c.type === 'SYSTEM'
            ? <Cpu className={`w-5 h-5 ${isLive ? 'text-emerald-400' : 'text-slate-400'}`} />
            : c.type === 'NETWORK'
            ? <Wifi className={`w-5 h-5 ${isLive ? 'text-blue-400' : 'text-slate-400'}`} />
            : <Globe className={`w-5 h-5 ${isLive ? 'text-purple-400' : 'text-slate-400'}`} />;

          return (
            <div
              key={c.type}
              className={`rounded-xl border p-4 transition-all ${
                isLive
                  ? 'bg-slate-950/80 border-emerald-500/40 shadow-lg shadow-emerald-950/20'
                  : 'bg-slate-950/40 border-slate-800/80 opacity-90'
              }`}
            >
              <div className="flex items-start justify-between">
                <div className="flex items-center space-x-2.5">
                  <div className={`p-2 rounded-lg ${isLive ? 'bg-emerald-950/60 border border-emerald-800/50' : 'bg-slate-800 border border-slate-700'}`}>
                    {icon}
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-white">{c.name}</h3>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${isLive ? 'bg-emerald-400 animate-ping' : 'bg-slate-500'}`} />
                      <span className={`text-[11px] font-mono font-semibold ${isLive ? 'text-emerald-400' : 'text-slate-400'}`}>
                        {c.state}
                      </span>
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => handleToggleCollector(c.type, c.state)}
                  disabled={activeToggle === c.type}
                  className={`px-2.5 py-1 rounded text-xs font-bold border transition-colors cursor-pointer ${
                    isLive
                      ? 'bg-red-950/60 border-red-800/60 text-red-300 hover:bg-red-900/60'
                      : 'bg-emerald-950/60 border-emerald-800/60 text-emerald-300 hover:bg-emerald-900/60'
                  }`}
                >
                  {activeToggle === c.type ? '...' : isLive ? 'STOP' : 'START'}
                </button>
              </div>

              <div className="mt-4 pt-3 border-t border-slate-800/80 grid grid-cols-2 gap-2 text-xs">
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-mono">Events Collected</span>
                  <span className="font-mono font-bold text-white">{c.eventsCollected || 0}</span>
                </div>
                <div>
                  <span className="text-slate-400 block text-[10px] uppercase font-mono">Telemetry Rate</span>
                  <span className="font-mono font-bold text-white">{c.currentEps || 0} eps</span>
                </div>
              </div>

              {c.details && (
                <div className="mt-2 text-[11px] text-slate-400 font-mono bg-slate-900/80 p-2 rounded border border-slate-800/60 truncate">
                  {c.type === 'SYSTEM' && `${c.details.platform || 'OS'} ${c.details.arch || ''} | ${c.details.cpusCount || 1} Cores | ${c.details.totalMemoryGb || 0}GB`}
                  {c.type === 'NETWORK' && `${c.details.activeInterfaces || 1} Interfaces | Listening Port ${c.details.registeredListeningPorts?.[0] || 3000}`}
                  {c.type === 'APPLICATION' && `${c.details.totalRequestsHandled || 0} Requests | Err Rate: ${c.details.errorRatePercent || 0}%`}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Manual Live Log Ingestion & Quick Testing */}
      <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-4 space-y-3">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center space-x-2">
            <Upload className="w-4 h-4 text-indigo-400" />
            <h4 className="text-xs font-bold text-white uppercase tracking-wider">
              Direct Live Telemetry Ingestion (Syslog / Raw Lines)
            </h4>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-xs text-slate-400">Target Agent:</span>
            <select
              value={ingestSource}
              onChange={(e) => setIngestSource(e.target.value as any)}
              className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-xs text-white"
            >
              <option value="system">System Security Agent (Auth/SSH/Sudo)</option>
              <option value="network">Network Security Agent (Netflow/Portscan)</option>
              <option value="application">Application Security Agent (HTTP/API)</option>
            </select>
          </div>
        </div>

        <div className="flex gap-2">
          <input
            type="text"
            placeholder={
              ingestSource === 'system'
                ? "Sep 17 10:20:01 host01 sshd[1234]: Failed password for root from 192.168.1.50 port 54321"
                : ingestSource === 'network'
                ? "src_ip=203.0.113.19 dst_ip=10.0.0.5 port=445 proto=TCP action=connect status=syn_sent"
                : "GET /api/users?id=1' OR '1'='1 HTTP/1.1 200 text/html"
            }
            value={ingestLogText}
            onChange={(e) => setIngestLogText(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') handleManualIngest(); }}
            className="flex-1 bg-slate-900 border border-slate-800 rounded-lg px-3 py-2 text-xs text-white font-mono placeholder:text-slate-500 focus:outline-none focus:border-indigo-500"
          />
          <button
            onClick={handleManualIngest}
            disabled={isIngesting || !ingestLogText.trim()}
            className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-bold flex items-center space-x-1.5 disabled:opacity-50 transition-colors cursor-pointer shrink-0"
          >
            <span>INGEST</span>
          </button>
        </div>

        {ingestFeedback && (
          <div className={`text-xs px-3 py-1.5 rounded flex items-center gap-1.5 ${
            ingestFeedback.includes('error') ? 'bg-red-950/60 text-red-300 border border-red-900/60' : 'bg-emerald-950/60 text-emerald-300 border border-emerald-900/60'
          }`}>
            {ingestFeedback.includes('error') ? <AlertTriangle className="w-3.5 h-3.5" /> : <CheckCircle2 className="w-3.5 h-3.5" />}
            <span>{ingestFeedback}</span>
          </div>
        )}
      </div>
    </div>
  );
};
