import React, { useState, useEffect } from 'react';
import { Shield, CheckCircle2, AlertCircle, Radio, Info } from 'lucide-react';
import { realtimeTelemetryStream } from '../../services/telemetry/realtimeTelemetryStream';
import { TelemetryStreamStatus } from '../../services/telemetry/telemetryTypes';

interface PipelineStatusBarProps {
  hasRealData?: boolean;
  totalEvents?: number;
}

export const PipelineStatusBar: React.FC<PipelineStatusBarProps> = ({
  hasRealData,
  totalEvents = 0
}) => {
  const [streamStatus, setStreamStatus] = useState<TelemetryStreamStatus>(realtimeTelemetryStream.getStatus());

  useEffect(() => {
    return realtimeTelemetryStream.onStatusChange((status) => {
      setStreamStatus(status);
    });
  }, []);

  const getStatusBadge = () => {
    switch (streamStatus) {
      case 'LIVE':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-950/60 text-emerald-400 border border-emerald-800">
            <CheckCircle2 className="w-3 h-3" />
            LIVE TELEMETRY STREAM ({totalEvents} Events)
          </span>
        );
      case 'CONNECTING':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-amber-950/60 text-amber-400 border border-amber-800">
            CONNECTING TO STREAM...
          </span>
        );
      case 'SIMULATION':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-indigo-950/60 text-indigo-400 border border-indigo-800">
            SIMULATION MODE
          </span>
        );
      case 'ERROR':
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-rose-950/60 text-rose-400 border border-rose-800">
            STREAM ERROR
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-slate-800 text-slate-400 border border-slate-700">
            STREAM DISCONNECTED (OFFLINE)
          </span>
        );
    }
  };

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-lg space-y-3">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3">
        {/* Left: Overall Ingestion Pipeline State */}
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-800 text-cyan-400">
            <Radio className="w-5 h-5 animate-pulse" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
                Stage 2 Pipeline Engine
              </span>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono font-bold bg-emerald-950/60 text-emerald-400 border border-emerald-800">
                <CheckCircle2 className="w-3 h-3" />
                ACTIVE
              </span>
              {getStatusBadge()}
            </div>
            <p className="text-xs text-slate-400 mt-0.5 font-mono">
              Real-time parser, normalizer, schema validator, and FNV-1a deduplicator
            </p>
          </div>
        </div>

        {/* Right: Explicit Sensor Daemon Statuses */}
        <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
          <div className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 flex items-center gap-1.5" title="Suricata live socket probe is simulated">
            <span className="text-slate-400">Suricata:</span>
            <span className="text-amber-400 font-bold bg-amber-950/40 px-1.5 py-0.2 rounded border border-amber-900/60 text-[10px]">
              DEMO / SIMULATED
            </span>
          </div>

          <div className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 flex items-center gap-1.5" title="Wazuh OSSEC agent daemon is simulated">
            <span className="text-slate-400">Wazuh:</span>
            <span className="text-amber-400 font-bold bg-amber-950/40 px-1.5 py-0.2 rounded border border-amber-900/60 text-[10px]">
              DEMO / SIMULATED
            </span>
          </div>

          <div className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 flex items-center gap-1.5" title="Sysmon WEF collection is simulated">
            <span className="text-slate-400">Sysmon:</span>
            <span className="text-amber-400 font-bold bg-amber-950/40 px-1.5 py-0.2 rounded border border-amber-900/60 text-[10px]">
              DEMO / SIMULATED
            </span>
          </div>

          <div className="px-2.5 py-1 rounded bg-slate-950 border border-slate-800 flex items-center gap-1.5" title="n8n webhook pipeline connector is simulated">
            <span className="text-slate-400">n8n:</span>
            <span className="text-amber-400 font-bold bg-amber-950/40 px-1.5 py-0.2 rounded border border-amber-900/60 text-[10px]">
              DEMO / SIMULATED
            </span>
          </div>
        </div>
      </div>

      {/* Honesty Disclosure Banner */}
      <div className="flex items-center gap-2 px-3 py-1.5 bg-slate-950/60 border border-slate-800/80 rounded-lg text-[11px] font-mono text-slate-400">
        <Info className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
        <span>
          <strong>Academic Major Project Disclosure:</strong> Uploaded log files (JSON, CSV, JSONL, Syslog) are executed through the live, authentic client-side parsing pipeline. External daemons (Suricata, Wazuh, Sysmon, n8n) are explicitly labeled DEMO / SIMULATED.
        </span>
      </div>
    </div>
  );
};
