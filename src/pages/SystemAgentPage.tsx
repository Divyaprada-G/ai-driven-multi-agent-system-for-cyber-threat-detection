import React, { useEffect, useState } from 'react';
import {
  Cpu,
  ShieldCheck,
  Activity,
  Play,
  Pause,
  RefreshCw,
  Upload,
  Users,
  Server,
  Clock,
  Info
} from 'lucide-react';
import { AgentStatusInfo, SystemAgentAnalysis, SystemAgentResult } from '../types';
import { systemAgentService } from '../services/systemAgentService';
import { StatusBadge } from '../components/common/StatusBadge';
import { SystemMetricsBar } from '../components/system-agent/SystemMetricsBar';
import { SystemCharts } from '../components/system-agent/SystemCharts';
import { UserActivityPanel } from '../components/system-agent/UserActivityPanel';
import { HostActivityPanel } from '../components/system-agent/HostActivityPanel';
import { SystemDetectionTable } from '../components/system-agent/SystemDetectionTable';
import { SystemTimeline } from '../components/system-agent/SystemTimeline';
import { SystemDetailModal } from '../components/system-agent/SystemDetailModal';
import { NavPageId } from '../components/layout/Sidebar';

interface SystemAgentPageProps {
  onNavigate?: (page: NavPageId) => void;
}

export const SystemAgentPage: React.FC<SystemAgentPageProps> = ({ onNavigate }) => {
  const [statusInfo, setStatusInfo] = useState<AgentStatusInfo | null>(null);
  const [analysis, setAnalysis] = useState<SystemAgentAnalysis | null>(null);
  const [selectedResult, setSelectedResult] = useState<SystemAgentResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'detections' | 'charts' | 'activity' | 'timeline'>('detections');

  const loadData = async () => {
    setLoading(true);
    try {
      const [st, ana] = await Promise.all([
        systemAgentService.getAgentStatus(),
        systemAgentService.getAnalysis()
      ]);
      setStatusInfo(st);
      setAnalysis(ana);
    } catch (err) {
      console.error('Error loading System Agent telemetry', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const unsubscribe = systemAgentService.subscribe(() => {
      loadData();
    });
    return () => unsubscribe();
  }, []);

  const handleToggle = async () => {
    const updated = await systemAgentService.toggleAgentStatus();
    setStatusInfo(updated);
  };

  if (loading && !analysis) {
    return (
      <div className="p-12 text-center text-slate-400 font-mono flex flex-col items-center justify-center gap-3">
        <RefreshCw className="w-6 h-6 text-emerald-400 animate-spin" />
        <span>Executing System Feature Extraction & Heuristics Pipeline...</span>
      </div>
    );
  }

  if (!statusInfo || !analysis) {
    return (
      <div className="p-8 text-center text-slate-500 font-mono">
        System Agent telemetry unavailable.
      </div>
    );
  }

  return (
    <div className="space-y-6" id="page-system-agent">
      {/* Agent Overview Header */}
      <div className="p-6 bg-slate-900/80 border border-emerald-500/30 rounded-xl space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3">
            <div className="p-3 bg-emerald-950/60 border border-emerald-800/60 rounded-xl text-emerald-400 shrink-0">
              <Cpu className="w-8 h-8" />
            </div>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h2 className="text-xl font-bold text-white tracking-tight">
                  {statusInfo.name}
                </h2>
                <StatusBadge status={statusInfo.status} type="agent" />

                {/* Clear Labeling: DEMO DATA vs REAL UPLOADED LOGS */}
                {analysis.isRealData ? (
                  <span className="px-2.5 py-0.5 rounded bg-emerald-950/80 border border-emerald-700/80 text-emerald-400 font-mono font-bold text-xs flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                    DATA SOURCE: {analysis.dataSource}
                  </span>
                ) : (
                  <span className="px-2.5 py-0.5 rounded bg-amber-950/80 border border-amber-700/80 text-amber-400 font-mono font-bold text-xs flex items-center gap-1.5">
                    <span className="w-2 h-2 rounded-full bg-amber-400" />
                    DEMO / SIMULATED DATA
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-1 font-mono">
                Subsystem: Endpoint Telemetry, Authentication Anomalies, Privilege Escalation & LOLBIN Process Heuristics
              </p>
            </div>
          </div>

          {/* Action Toolbar */}
          <div className="flex items-center gap-2 flex-wrap">
            <button
              id="btn-refresh-system-telemetry"
              onClick={loadData}
              title="Re-run heuristic extraction"
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5 text-emerald-400" />
              <span>Re-analyze</span>
            </button>

            <button
              id="btn-toggle-system-agent"
              onClick={handleToggle}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono font-medium bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
            >
              {statusInfo.status === 'READY' ? (
                <>
                  <Pause className="w-3.5 h-3.5 text-amber-400" />
                  <span>Pause Agent</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Resume Agent</span>
                </>
              )}
            </button>

            {onNavigate && (
              <button
                id="btn-system-goto-log-explorer"
                onClick={() => onNavigate('log-explorer')}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-lg shadow-emerald-600/20 transition-colors"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Upload Host Logs</span>
              </button>
            )}
          </div>
        </div>

        {/* Baseline Status Banner */}
        <div className="flex items-center gap-2 px-3 py-2 bg-slate-950/60 rounded-lg border border-slate-800 text-xs font-mono text-slate-300">
          <Info className="w-4 h-4 text-cyan-400 shrink-0" />
          <span>Operational Baseline: {analysis.baselineStatus}</span>
        </div>

        <div className="pt-2 border-t border-slate-800 text-xs text-slate-300 leading-relaxed font-sans">
          {statusInfo.description}
        </div>
      </div>

      {/* Metrics Bar */}
      <SystemMetricsBar analysis={analysis} />

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 text-xs font-mono flex-wrap">
        <button
          id="subtab-system-detections"
          onClick={() => setActiveTab('detections')}
          className={`px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'detections'
              ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 font-bold'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900/60 border border-transparent'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Detections Table ({analysis.results.length})</span>
        </button>

        <button
          id="subtab-system-charts"
          onClick={() => setActiveTab('charts')}
          className={`px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'charts'
              ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 font-bold'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900/60 border border-transparent'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Authentication & Host Analytics</span>
        </button>

        <button
          id="subtab-system-activity"
          onClick={() => setActiveTab('activity')}
          className={`px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'activity'
              ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 font-bold'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900/60 border border-transparent'
          }`}
        >
          <Users className="w-3.5 h-3.5" />
          <span>User & Host Profiling</span>
        </button>

        <button
          id="subtab-system-timeline"
          onClick={() => setActiveTab('timeline')}
          className={`px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'timeline'
              ? 'bg-emerald-950/80 text-emerald-300 border border-emerald-800/80 font-bold'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900/60 border border-transparent'
          }`}
        >
          <Clock className="w-3.5 h-3.5" />
          <span>System Timeline ({analysis.timeline.length})</span>
        </button>
      </div>

      {/* Main Tab Content */}
      {activeTab === 'detections' && (
        <SystemDetectionTable
          results={analysis.results}
          onSelectResult={setSelectedResult}
        />
      )}

      {activeTab === 'charts' && (
        <SystemCharts analysis={analysis} />
      )}

      {activeTab === 'activity' && (
        <div className="space-y-6">
          <UserActivityPanel userActivity={analysis.userActivity} />
          <HostActivityPanel hostActivity={analysis.hostActivity} />
        </div>
      )}

      {activeTab === 'timeline' && (
        <SystemTimeline timeline={analysis.timeline} />
      )}

      {/* Detection Inspection Modal */}
      <SystemDetailModal
        result={selectedResult}
        onClose={() => setSelectedResult(null)}
      />
    </div>
  );
};
