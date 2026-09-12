import React, { useState } from 'react';
import {
  Play,
  Square,
  Sparkles,
  RotateCcw,
  RefreshCw,
  Sliders,
  ShieldAlert,
  Radio,
  SlidersHorizontal,
  Flame,
  Info,
  Layers
} from 'lucide-react';
import { LivePipelineStatus, LiveSimulatorMode } from '../../types/livePipeline';

interface LivePipelineControlsProps {
  status: LivePipelineStatus;
  onStartPipeline: () => void;
  onStopPipeline: () => void;
  onStartSimulator: (rate: number, mode: LiveSimulatorMode) => void;
  onStopSimulator: () => void;
  onClearEvents: () => void;
  onRefreshStatus: () => void;
  onRunDemo: () => void;
}

export const LivePipelineControls: React.FC<LivePipelineControlsProps> = ({
  status,
  onStartPipeline,
  onStopPipeline,
  onStartSimulator,
  onStopSimulator,
  onClearEvents,
  onRefreshStatus,
  onRunDemo
}) => {
  const [rate, setRate] = useState<number>(status.simulatorRate || 2);
  const [mode, setMode] = useState<LiveSimulatorMode>(status.simulatorMode || 'mixed');

  const handleToggleSimulator = () => {
    if (status.simulatorActive) {
      onStopSimulator();
    } else {
      onStartSimulator(rate, mode);
    }
  };

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm space-y-4">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 border-b border-slate-800 pb-3">
        <div>
          <div className="flex items-center space-x-2">
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">Live Pipeline & Simulator Controls</h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-sky-500/20 text-sky-300 font-mono border border-sky-500/30">
              100% Free / Local API
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Orchestrates event ingestion, multi-agent evaluation, real-time ML inference, and alert generation.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex flex-wrap items-center gap-2">
          {/* One-Click Run Demo Button */}
          <button
            onClick={onRunDemo}
            className="px-3 py-1.5 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-semibold flex items-center space-x-1.5 shadow-md shadow-indigo-950 transition-all cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>RUN PROJECT DEMO</span>
          </button>

          {/* Start/Stop Pipeline */}
          {status.status === 'RUNNING' ? (
            <button
              onClick={onStopPipeline}
              className="px-3 py-1.5 rounded-lg bg-red-500/20 hover:bg-red-500/30 text-red-300 border border-red-500/30 text-xs font-medium flex items-center space-x-1.5 transition-colors cursor-pointer"
            >
              <Square className="w-3.5 h-3.5 text-red-400" />
              <span>STOP PIPELINE</span>
            </button>
          ) : (
            <button
              onClick={onStartPipeline}
              className="px-3 py-1.5 rounded-lg bg-emerald-500/20 hover:bg-emerald-500/30 text-emerald-300 border border-emerald-500/30 text-xs font-medium flex items-center space-x-1.5 transition-colors cursor-pointer"
            >
              <Play className="w-3.5 h-3.5 text-emerald-400" />
              <span>START PIPELINE</span>
            </button>
          )}

          {/* Clear Events */}
          <button
            onClick={onClearEvents}
            className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-medium flex items-center space-x-1 transition-colors cursor-pointer"
            title="Clear live events stream and performance counters"
          >
            <RotateCcw className="w-3.5 h-3.5" />
            <span>Clear</span>
          </button>

          {/* Refresh Status */}
          <button
            onClick={onRefreshStatus}
            className="p-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 text-xs font-medium transition-colors cursor-pointer"
            title="Refresh local backend health and telemetry"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Simulator Control Configuration Strip */}
      <div className="bg-slate-950/60 border border-slate-800/80 rounded-lg p-3 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center space-x-2">
            <Radio className={`w-4 h-4 ${status.simulatorActive ? 'text-amber-400 animate-pulse' : 'text-slate-500'}`} />
            <span className="text-xs font-semibold text-slate-200">Local Event Simulator:</span>
            <span className={`text-xs px-2 py-0.5 rounded font-mono ${
              status.simulatorActive
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30'
                : 'bg-slate-800 text-slate-400'
            }`}>
              {status.simulatorActive ? 'STREAMING' : 'IDLE'}
            </span>
          </div>

          {/* Event Rate Selector */}
          <div className="flex items-center space-x-1.5 text-xs text-slate-400">
            <span>Rate:</span>
            <div className="flex rounded-md bg-slate-900 border border-slate-800 p-0.5">
              {[1, 2, 5, 10].map((r) => (
                <button
                  key={r}
                  disabled={status.simulatorActive}
                  onClick={() => {
                    setRate(r);
                    if (status.simulatorActive) onStartSimulator(r, mode);
                  }}
                  className={`px-2 py-0.5 text-xs rounded font-mono transition-colors ${
                    rate === r
                      ? 'bg-sky-500 text-white font-bold'
                      : 'text-slate-400 hover:text-slate-200 disabled:opacity-60'
                  }`}
                >
                  {r}/s
                </button>
              ))}
            </div>
          </div>

          {/* Mode Selector */}
          <div className="flex items-center space-x-1.5 text-xs text-slate-400">
            <span>Mode:</span>
            <select
              value={mode}
              disabled={status.simulatorActive}
              onChange={(e) => {
                const newMode = e.target.value as LiveSimulatorMode;
                setMode(newMode);
                if (status.simulatorActive) onStartSimulator(rate, newMode);
              }}
              className="bg-slate-900 border border-slate-700 text-slate-200 text-xs rounded-md px-2 py-1 outline-none focus:border-sky-500 disabled:opacity-60"
            >
              <option value="mixed">Mixed Events (Default)</option>
              <option value="suspicious">Suspicious Events Only</option>
              <option value="normal">Normal Events (Benign)</option>
              <option value="multistage">Multi-Stage Attack Chain</option>
            </select>
          </div>
        </div>

        {/* Toggle Simulator Button */}
        <div className="flex items-center space-x-2">
          <button
            onClick={handleToggleSimulator}
            className={`px-3 py-1.5 rounded-lg text-xs font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer ${
              status.simulatorActive
                ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30 hover:bg-amber-500/30'
                : 'bg-sky-500/20 text-sky-300 border border-sky-500/30 hover:bg-sky-500/30'
            }`}
          >
            {status.simulatorActive ? <Square className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
            <span>{status.simulatorActive ? 'STOP SIMULATOR' : 'START SIMULATOR'}</span>
          </button>
        </div>
      </div>

      {/* Mandatory Academic & Safety Disclaimer */}
      <div className="flex items-start space-x-2 text-[11px] text-slate-400 bg-slate-950/40 border border-slate-800/60 rounded-lg p-2.5">
        <Info className="w-4 h-4 text-sky-400 shrink-0 mt-0.5" />
        <div className="leading-relaxed">
          <span className="text-slate-300 font-medium">SIMULATED SECURITY EVENTS: </span>
          Synthetic network, system, and application flows generated locally to validate ML inference and multi-agent coordination.
          <span className="text-emerald-400 font-semibold ml-1">SIMULATION ONLY:</span> Recommended defensive responses are purely informational. Zero real network packets, firewall rules, or host processes are altered.
        </div>
      </div>
    </div>
  );
};
