import React from 'react';
import {
  Server,
  Activity,
  ShieldAlert,
  AlertTriangle,
  Zap,
  CheckCircle2,
  XCircle,
  Clock,
  Radio,
  Cpu,
  RefreshCw,
  Sliders,
  Play,
  Square,
  AlertOctagon,
  Bell,
  Terminal,
  Database
} from 'lucide-react';
import { LivePipelineStatus } from '../../types/livePipeline';

interface LivePipelineStatusCardProps {
  status: LivePipelineStatus;
  onRefresh: () => void;
  onNavigateToTraining: () => void;
}

export const LivePipelineStatusCard: React.FC<LivePipelineStatusCardProps> = ({
  status,
  onRefresh,
  onNavigateToTraining
}) => {
  return (
    <div className="space-y-4">
      {/* Offline Instructions Alert if Backend is Offline */}
      {!status.backendOnline && (
        <div className="bg-amber-950/40 border border-amber-500/40 rounded-xl p-4 text-amber-200">
          <div className="flex items-start justify-between">
            <div className="flex items-start space-x-3">
              <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400 mt-0.5">
                <Terminal className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <span className="font-semibold text-amber-300">LOCAL ML BACKEND OFFLINE</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    Optional Standalone API
                  </span>
                </div>
                <p className="text-xs text-amber-300/80 mt-1">
                  The local FastAPI server at <code className="bg-black/40 px-1 py-0.5 rounded text-amber-200">{status.backendUrl}</code> is not currently running. The platform seamlessly processes live events and trained models using the built-in browser engine.
                </p>
                <div className="mt-2 text-xs font-mono bg-black/60 p-2.5 rounded-lg border border-amber-500/20 text-slate-300 space-y-1">
                  <p className="text-amber-400 font-semibold">To launch the local Python FastAPI server:</p>
                  <p className="text-slate-300">1. Open terminal: <span className="text-emerald-400">cd backend</span></p>
                  <p className="text-slate-300">2. Start server: <span className="text-emerald-400">uvicorn main:app --reload --port 8000</span></p>
                  <p className="text-slate-300">3. Interactive Docs available at: <span className="text-sky-400">http://127.0.0.1:8000/docs</span></p>
                </div>
              </div>
            </div>
            <button
              onClick={onRefresh}
              className="px-3 py-1.5 rounded-lg bg-amber-500/20 hover:bg-amber-500/30 text-amber-300 border border-amber-500/30 text-xs font-medium flex items-center space-x-1.5 transition-colors shrink-0"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Connection</span>
            </button>
          </div>
        </div>
      )}

      {/* Top Telemetry Header Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Backend Status */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>FastAPI Backend</span>
            <Server className="w-3.5 h-3.5 text-slate-500" />
          </div>
          <div className="flex items-center space-x-2">
            <span className={`w-2 h-2 rounded-full ${status.backendOnline ? 'bg-emerald-400 animate-pulse' : 'bg-slate-500'}`} />
            <span className={`text-sm font-bold ${status.backendOnline ? 'text-emerald-400' : 'text-slate-400'}`}>
              {status.backendOnline ? 'ONLINE' : 'OFFLINE'}
            </span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1 truncate">{status.backendUrl}</p>
        </div>

        {/* ML Engine Status */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>ML Engine</span>
            <Cpu className="w-3.5 h-3.5 text-slate-500" />
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400" />
            <span className="text-sm font-bold text-slate-100">
              {status.backendOnline ? 'ONLINE' : 'READY'}
            </span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">Scikit-Learn ML</p>
        </div>

        {/* Model Status */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Active Model</span>
            <Database className="w-3.5 h-3.5 text-slate-500" />
          </div>
          <div className="flex items-center space-x-1.5 truncate">
            <span className="text-sm font-bold text-sky-400 truncate">
              {status.activeModelType === 'ISOLATION_FOREST' ? 'Isolation Forest' : 'Random Forest'}
            </span>
          </div>
          <div className="flex items-center justify-between mt-1">
            <span className={`text-[10px] font-semibold px-1.5 py-0.5 rounded ${
              status.activeModelStatus === 'TRAINED' || status.activeModelStatus === 'MODEL_READY'
                ? 'bg-emerald-500/20 text-emerald-300'
                : (status.activeModelStatus === 'MODEL_ERROR' ? 'bg-red-500/20 text-red-300' : 'bg-amber-500/20 text-amber-300')
            }`}>
              {status.activeModelStatus === 'TRAINED' || status.activeModelStatus === 'MODEL_READY'
                ? 'MODEL READY'
                : (status.activeModelStatus === 'MODEL_ERROR' ? 'MODEL ERROR' : 'MODEL NOT READY')}
            </span>
            <button
              onClick={onNavigateToTraining}
              className="text-[10px] text-sky-400 hover:text-sky-300 underline"
            >
              Config
            </button>
          </div>
        </div>

        {/* Pipeline Status */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Pipeline State</span>
            <Radio className="w-3.5 h-3.5 text-slate-500" />
          </div>
          <div className="flex items-center space-x-2">
            <span className={`w-2 h-2 rounded-full ${status.status === 'RUNNING' ? 'bg-emerald-400 animate-ping' : 'bg-slate-500'}`} />
            <span className={`text-sm font-bold ${status.status === 'RUNNING' ? 'text-emerald-400' : 'text-slate-400'}`}>
              {status.status}
            </span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">Queue: {status.queueLength}</p>
        </div>

        {/* Processing Throughput */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Throughput</span>
            <Zap className="w-3.5 h-3.5 text-amber-500" />
          </div>
          <div className="text-sm font-bold text-amber-400">
            {status.eventsPerSecond} <span className="text-xs font-normal text-slate-400">evt/s</span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">{status.eventsProcessed} processed</p>
        </div>

        {/* Processing Latency */}
        <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-3.5">
          <div className="flex items-center justify-between text-xs text-slate-400 mb-1">
            <span>Avg Latency</span>
            <Clock className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-sm font-bold text-cyan-400">
            {status.averageLatencyMs} <span className="text-xs font-normal text-slate-400">ms</span>
          </div>
          <p className="text-[10px] text-slate-500 mt-1">Min: {status.minLatencyMs}ms | Max: {status.maxLatencyMs}ms</p>
        </div>
      </div>

      {/* Primary KPI Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-3">
          <span className="text-xs text-slate-400">Events Received</span>
          <p className="text-2xl font-bold text-slate-100 mt-1">{status.eventsReceived}</p>
          <span className="text-[10px] text-slate-500">Total ingested</span>
        </div>

        <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-3">
          <span className="text-xs text-slate-400">Events Processed</span>
          <p className="text-2xl font-bold text-emerald-400 mt-1">{status.eventsProcessed}</p>
          <span className="text-[10px] text-emerald-500/70">Through multi-agents</span>
        </div>

        <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-3">
          <span className="text-xs text-slate-400">Threats Detected</span>
          <p className="text-2xl font-bold text-rose-400 mt-1">{status.threatsDetected}</p>
          <span className="text-[10px] text-rose-500/70">ML positive detections</span>
        </div>

        <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-3">
          <span className="text-xs text-slate-400">Alerts Generated</span>
          <p className="text-2xl font-bold text-amber-400 mt-1">{status.alertsGenerated}</p>
          <span className="text-[10px] text-amber-500/70">Risk score ≥ 40</span>
        </div>

        <div className="bg-slate-900/70 border border-slate-800/80 rounded-xl p-3">
          <span className="text-xs text-slate-400">Incidents Created</span>
          <p className="text-2xl font-bold text-red-500 mt-1">{status.incidentsCreated}</p>
          <span className="text-[10px] text-red-400/70">Escalated (Risk ≥ 70)</span>
        </div>
      </div>
    </div>
  );
};
