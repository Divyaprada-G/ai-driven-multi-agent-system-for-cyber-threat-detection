import React, { useState, useEffect } from 'react';
import {
  Radio,
  Loader2,
  WifiOff,
  AlertOctagon,
  FlaskConical,
  CheckCircle2,
  Server
} from 'lucide-react';
import {
  realtimeTelemetryStream,
  TelemetryStreamMetrics
} from '../../services/telemetry/realtimeTelemetryStream';
import { TelemetryStreamStatus } from '../../services/telemetry/telemetryTypes';

interface TelemetryStatusBadgeProps {
  showDetails?: boolean;
  className?: string;
}

export const TelemetryStatusBadge: React.FC<TelemetryStatusBadgeProps> = ({
  showDetails = true,
  className = ''
}) => {
  const [status, setStatus] = useState<TelemetryStreamStatus>(realtimeTelemetryStream.getStatus());
  const [details, setDetails] = useState<any>({});
  const [metrics, setMetrics] = useState<TelemetryStreamMetrics>(realtimeTelemetryStream.getMetrics());

  useEffect(() => {
    const unsubStatus = realtimeTelemetryStream.onStatusChange((newStatus, meta) => {
      setStatus(newStatus);
      setDetails(meta || {});
    });

    const unsubMetrics = realtimeTelemetryStream.onMetrics((newMetrics) => {
      setMetrics(newMetrics);
    });

    return () => {
      unsubStatus();
      unsubMetrics();
    };
  }, []);

  // Configuration for all 5 verified telemetry stream states
  const config = {
    LIVE: {
      label: 'LIVE',
      icon: <Radio className="w-3.5 h-3.5 text-emerald-400 animate-pulse" />,
      dotClass: 'bg-emerald-400',
      badgeClass: 'border-emerald-500/40 bg-emerald-950/50 text-emerald-300 shadow-[0_0_12px_rgba(16,185,129,0.2)]',
      description: 'Stream verified and receiving authentic host telemetry'
    },
    CONNECTING: {
      label: 'CONNECTING',
      icon: <Loader2 className="w-3.5 h-3.5 text-amber-400 animate-spin" />,
      dotClass: 'bg-amber-400',
      badgeClass: 'border-amber-500/40 bg-amber-950/50 text-amber-300 shadow-[0_0_12px_rgba(245,158,11,0.2)]',
      description: details.reason || 'Establishing SSE telemetry stream...'
    },
    DISCONNECTED: {
      label: 'DISCONNECTED',
      icon: <WifiOff className="w-3.5 h-3.5 text-slate-400" />,
      dotClass: 'bg-slate-500',
      badgeClass: 'border-slate-700 bg-slate-900/80 text-slate-400',
      description: details.reason || 'Stream disconnected. Waiting for connection...'
    },
    SIMULATION: {
      label: 'SIMULATION',
      icon: <FlaskConical className="w-3.5 h-3.5 text-indigo-400" />,
      dotClass: 'bg-indigo-400',
      badgeClass: 'border-indigo-500/40 bg-indigo-950/50 text-indigo-300 shadow-[0_0_12px_rgba(99,102,241,0.2)]',
      description: 'Stream active in simulated demonstration mode'
    },
    ERROR: {
      label: 'ERROR',
      icon: <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />,
      dotClass: 'bg-rose-500',
      badgeClass: 'border-rose-500/40 bg-rose-950/50 text-rose-300 shadow-[0_0_12px_rgba(244,63,94,0.2)]',
      description: details.reason || 'Telemetry stream error encountered'
    }
  };

  const current = config[status] || config.DISCONNECTED;

  return (
    <div
      id="telemetry-status-indicator"
      className={`inline-flex items-center gap-2 px-3 py-1 rounded-full border text-xs font-mono font-bold tracking-wider transition-all duration-300 ${current.badgeClass} ${className}`}
      title={current.description}
    >
      <div className="relative flex items-center justify-center">
        {status === 'LIVE' && (
          <span className={`w-2 h-2 rounded-full ${current.dotClass} animate-ping absolute opacity-75`} />
        )}
        <span className={`w-2 h-2 rounded-full ${current.dotClass}`} />
      </div>

      <span className="font-semibold">{current.label}</span>

      {showDetails && status === 'LIVE' && (
        <span className="text-[11px] text-emerald-400/80 font-normal pl-1 border-l border-emerald-500/30">
          {metrics.totalLiveEvents} EVTS {metrics.currentEps > 0 ? `• ${metrics.currentEps} EPS` : ''}
        </span>
      )}

      {showDetails && status === 'CONNECTING' && details.attempts > 0 && (
        <span className="text-[10px] text-amber-300/80 font-normal">
          (retry #{details.attempts})
        </span>
      )}
    </div>
  );
};
