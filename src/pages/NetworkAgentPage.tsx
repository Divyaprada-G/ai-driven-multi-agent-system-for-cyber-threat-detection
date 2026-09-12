import React, { useEffect, useState } from 'react';
import { Network, ShieldCheck, Activity, AlertTriangle, Radio, Play, Pause, RefreshCw, Upload, FileText } from 'lucide-react';
import { AgentStatusInfo, NetworkAgentAnalysis, NetworkAgentResult } from '../types';
import { networkAgentService } from '../services/networkAgentService';
import { StatusBadge } from '../components/common/StatusBadge';
import { NetworkMetricsBar } from '../components/network-agent/NetworkMetricsBar';
import { NetworkCharts } from '../components/network-agent/NetworkCharts';
import { TopTalkersPanel } from '../components/network-agent/TopTalkersPanel';
import { NetworkDetectionTable } from '../components/network-agent/NetworkDetectionTable';
import { NetworkTimeline } from '../components/network-agent/NetworkTimeline';
import { NetworkDetailModal } from '../components/network-agent/NetworkDetailModal';
import { NavPageId } from '../components/layout/Sidebar';

interface NetworkAgentPageProps {
  onNavigate?: (page: NavPageId) => void;
}

export const NetworkAgentPage: React.FC<NetworkAgentPageProps> = ({ onNavigate }) => {
  const [statusInfo, setStatusInfo] = useState<AgentStatusInfo | null>(null);
  const [analysis, setAnalysis] = useState<NetworkAgentAnalysis | null>(null);
  const [selectedResult, setSelectedResult] = useState<NetworkAgentResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'detections' | 'charts' | 'talkers' | 'timeline'>('detections');

  const loadData = async () => {
    setLoading(true);
    try {
      const [st, ana] = await Promise.all([
        networkAgentService.getAgentStatus(),
        networkAgentService.getAnalysis()
      ]);
      setStatusInfo(st);
      setAnalysis(ana);
    } catch (err) {
      console.error('Error loading Network Agent telemetry', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    // Subscribe to reactive log changes
    const unsubscribe = networkAgentService.subscribe(() => {
      loadData();
    });
    return () => unsubscribe();
  }, []);

  const handleToggle = async () => {
    const updated = await networkAgentService.toggleAgentStatus();
    setStatusInfo(updated);
  };

  if (loading && !analysis) {
    return (
      <div className="p-12 text-center text-slate-400 font-mono flex flex-col items-center justify-center gap-3">
        <RefreshCw className="w-6 h-6 text-cyan-400 animate-spin" />
        <span>Executing Network Feature Extraction & Heuristics Pipeline...</span>
      </div>
    );
  }

  if (!statusInfo || !analysis) {
    return (
      <div className="p-8 text-center text-slate-500 font-mono">
        Network Agent telemetry unavailable.
      </div>
    );
  }

  return (
    <div className="space-y-6" id="page-network-agent">
      {/* Agent Overview Header */}
      <div className="p-6 bg-slate-900/80 border border-cyan-500/30 rounded-xl space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3">
            <div className="p-3 bg-cyan-950/60 border border-cyan-800/60 rounded-xl text-cyan-400 shrink-0">
              <Network className="w-8 h-8" />
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
                Subsystem: Flow Feature Extraction, Port Scan Sweep Heuristics & Anomaly Baseline Detection
              </p>
            </div>
          </div>

          {/* Action Toolbar */}
          <div className="flex items-center gap-2 flex-wrap">
            <button
              id="btn-refresh-network-telemetry"
              onClick={loadData}
              title="Re-run heuristic extraction"
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
              <span>Re-analyze</span>
            </button>

            <button
              id="btn-toggle-network-agent"
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
                id="btn-goto-log-explorer"
                onClick={() => onNavigate('log-explorer')}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono font-semibold bg-cyan-600 hover:bg-cyan-500 text-white shadow-lg shadow-cyan-600/20 transition-colors"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Upload Logs</span>
              </button>
            )}
          </div>
        </div>

        <div className="pt-3 border-t border-slate-800 text-xs text-slate-300 leading-relaxed font-sans">
          {statusInfo.description}
        </div>
      </div>

      {/* 6 Key Metrics Required by Stage 3 */}
      <NetworkMetricsBar analysis={analysis} />

      {/* Navigation Sub-Tabs */}
      <div className="flex items-center gap-2 border-b border-slate-800 pb-2 text-xs font-mono">
        <button
          id="subtab-detections"
          onClick={() => setActiveTab('detections')}
          className={`px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'detections'
              ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/80 font-bold'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900/60 border border-transparent'
          }`}
        >
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Detections Table ({analysis.results.length})</span>
        </button>

        <button
          id="subtab-charts"
          onClick={() => setActiveTab('charts')}
          className={`px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'charts'
              ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/80 font-bold'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900/60 border border-transparent'
          }`}
        >
          <Activity className="w-3.5 h-3.5" />
          <span>Network Charts & Distributions</span>
        </button>

        <button
          id="subtab-talkers"
          onClick={() => setActiveTab('talkers')}
          className={`px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'talkers'
              ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/80 font-bold'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900/60 border border-transparent'
          }`}
        >
          <Radio className="w-3.5 h-3.5" />
          <span>Top Talkers Analysis</span>
        </button>

        <button
          id="subtab-timeline"
          onClick={() => setActiveTab('timeline')}
          className={`px-3 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 ${
            activeTab === 'timeline'
              ? 'bg-cyan-950/80 text-cyan-300 border border-cyan-800/80 font-bold'
              : 'text-slate-400 hover:text-slate-200 bg-slate-900/60 border border-transparent'
          }`}
        >
          <FileText className="w-3.5 h-3.5" />
          <span>Network Timeline</span>
        </button>
      </div>

      {/* Main Tab Content */}
      {activeTab === 'detections' && (
        <div className="space-y-6">
          <NetworkDetectionTable
            results={analysis.results}
            onSelectResult={res => setSelectedResult(res)}
          />
          {/* Also show mini-preview of charts below the table */}
          <NetworkCharts analysis={analysis} />
        </div>
      )}

      {activeTab === 'charts' && (
        <div className="space-y-6">
          <NetworkCharts analysis={analysis} />
          <TopTalkersPanel
            topSources={analysis.topSourceIps}
            topDestinations={analysis.topDestinationIps}
          />
        </div>
      )}

      {activeTab === 'talkers' && (
        <TopTalkersPanel
          topSources={analysis.topSourceIps}
          topDestinations={analysis.topDestinationIps}
        />
      )}

      {activeTab === 'timeline' && (
        <NetworkTimeline
          timeline={analysis.timeline}
          onSelectFinding={id => {
            const found = analysis.results.find(r => r.id === id);
            if (found) setSelectedResult(found);
          }}
        />
      )}

      {/* Detection Detail Modal */}
      {selectedResult && (
        <NetworkDetailModal
          result={selectedResult}
          onClose={() => setSelectedResult(null)}
        />
      )}
    </div>
  );
};
