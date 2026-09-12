import React, { useEffect, useState } from 'react';
import {
  Globe,
  ShieldCheck,
  Activity,
  Play,
  Pause,
  RefreshCw,
  Upload,
  BarChart3,
  Server,
  Clock,
  Info,
  Layers,
  Users
} from 'lucide-react';
import { AgentStatusInfo } from '../types';
import { ApplicationAgentAnalysis, ApplicationAgentResult } from '../types/application';
import { applicationAgentService } from '../services/applicationAgentService';
import { StatusBadge } from '../components/common/StatusBadge';
import { ApplicationMetricsBar } from '../components/application-agent/ApplicationMetricsBar';
import { ApplicationCharts } from '../components/application-agent/ApplicationCharts';
import { ApplicationDetectionTable } from '../components/application-agent/ApplicationDetectionTable';
import { EndpointActivityPanel } from '../components/application-agent/EndpointActivityPanel';
import { SourceIpActivityPanel } from '../components/application-agent/SourceIpActivityPanel';
import { UserAppActivityPanel } from '../components/application-agent/UserAppActivityPanel';
import { ApplicationTimeline } from '../components/application-agent/ApplicationTimeline';
import { ApplicationDetailModal } from '../components/application-agent/ApplicationDetailModal';
import { NavPageId } from '../components/layout/Sidebar';

interface ApplicationAgentPageProps {
  onNavigate?: (page: NavPageId) => void;
}

export const ApplicationAgentPage: React.FC<ApplicationAgentPageProps> = ({ onNavigate }) => {
  const [statusInfo, setStatusInfo] = useState<AgentStatusInfo | null>(null);
  const [analysis, setAnalysis] = useState<ApplicationAgentAnalysis | null>(null);
  const [selectedResult, setSelectedResult] = useState<ApplicationAgentResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState<'detections' | 'charts' | 'endpoints' | 'sources' | 'users' | 'timeline'>('detections');

  const loadData = async () => {
    setLoading(true);
    try {
      const [st, ana] = await Promise.all([
        applicationAgentService.getAgentStatus(),
        applicationAgentService.getAnalysis()
      ]);
      setStatusInfo(st);
      setAnalysis(ana);
    } catch (err) {
      console.error('Error loading Application Agent telemetry', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    const unsubscribe = applicationAgentService.subscribe(() => {
      loadData();
    });
    return () => unsubscribe();
  }, []);

  const handleToggle = async () => {
    const updated = await applicationAgentService.toggleAgentStatus();
    setStatusInfo(updated);
  };

  if (loading && !analysis) {
    return (
      <div className="p-12 text-center text-slate-400 font-mono flex flex-col items-center justify-center gap-3">
        <RefreshCw className="w-6 h-6 text-indigo-400 animate-spin" />
        <span>Executing Application Feature Extraction & Threat Detection Pipeline...</span>
      </div>
    );
  }

  if (!statusInfo || !analysis) {
    return (
      <div className="p-8 text-center text-slate-500 font-mono">
        Application Agent telemetry unavailable.
      </div>
    );
  }

  return (
    <div className="space-y-6" id="page-application-agent">
      {/* Agent Overview Header */}
      <div className="p-6 bg-slate-900/80 border border-indigo-500/30 rounded-xl space-y-4">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div className="flex items-start sm:items-center gap-3">
            <div className="p-3 bg-indigo-950/60 border border-indigo-800/60 rounded-xl text-indigo-400 shrink-0">
              <Globe className="w-8 h-8" />
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
                Subsystem: HTTP/S Web Applications, REST/GraphQL APIs, OWASP Injection Heuristics & Rate-Limit Anomaly Detection
              </p>
            </div>
          </div>

          {/* Action Toolbar */}
          <div className="flex items-center gap-2 flex-wrap">
            {onNavigate && (
              <button
                id="btn-upload-app-logs"
                onClick={() => onNavigate('log-explorer')}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono font-medium bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-300 border border-indigo-500/40 transition-colors"
                title="Upload custom web/API logs"
              >
                <Upload className="w-3.5 h-3.5" />
                <span>Ingest Logs</span>
              </button>
            )}

            <button
              id="btn-refresh-app-agent"
              onClick={loadData}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-mono font-medium bg-slate-800 hover:bg-slate-750 text-slate-300 border border-slate-750 transition-colors"
              title="Refresh telemetry"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
              <span>Refresh</span>
            </button>

            <button
              id="btn-toggle-app-agent"
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
                  <Play className="w-3.5 h-3.5 text-indigo-400" />
                  <span>Resume Agent</span>
                </>
              )}
            </button>
          </div>
        </div>

        <div className="pt-3 border-t border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs text-slate-400">
          <div className="flex items-center gap-4 flex-wrap">
            <span>Uptime: <strong className="text-slate-200">{statusInfo.uptime}</strong></span>
            <span>Active Rules: <strong className="text-slate-200">{statusInfo.activeRulesCount} Heuristics</strong></span>
            <span>Engine: <strong className="text-slate-200">OWASP ModSec Tokenizer + Behavioral Sliding-Window</strong></span>
          </div>
          <div className="text-slate-400 text-[11px] font-mono">
            Baseline Status: <span className="text-indigo-400">{analysis.baselineStatus}</span>
          </div>
        </div>
      </div>

      {/* Metrics Bar */}
      <ApplicationMetricsBar analysis={analysis} />

      {/* Defensive Advisory Banner */}
      <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 flex items-start gap-3">
        <Info className="w-4 h-4 text-indigo-500 shrink-0 mt-0.5" />
        <div className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed">
          <span className="font-semibold text-slate-800 dark:text-slate-200">Defensive Analytics Notice: </span>
          The Application Agent analyzes ingress HTTP/HTTPS request metadata, payload tokens, status patterns, and authentication attempts passively. It does not execute requests against external servers, inject test exploits, or automatically manipulate backend databases. All recommended mitigation steps are informational advisories.
        </div>
      </div>

      {/* Main Tabs Navigation */}
      <div className="flex border-b border-slate-200 dark:border-slate-800 gap-1 overflow-x-auto">
        <button
          id="app-tab-detections"
          onClick={() => setActiveTab('detections')}
          className={`px-4 py-2.5 text-xs font-semibold border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
            activeTab === 'detections'
              ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400 bg-indigo-50/50 dark:bg-indigo-950/20 rounded-t-lg'
              : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          <ShieldCheck className="w-4 h-4" />
          Detections & Findings ({analysis.results.length})
        </button>

        <button
          id="app-tab-charts"
          onClick={() => setActiveTab('charts')}
          className={`px-4 py-2.5 text-xs font-semibold border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
            activeTab === 'charts'
              ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400 bg-indigo-50/50 dark:bg-indigo-950/20 rounded-t-lg'
              : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          <BarChart3 className="w-4 h-4" />
          Visual Analytics & Distributions
        </button>

        <button
          id="app-tab-endpoints"
          onClick={() => setActiveTab('endpoints')}
          className={`px-4 py-2.5 text-xs font-semibold border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
            activeTab === 'endpoints'
              ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400 bg-indigo-50/50 dark:bg-indigo-950/20 rounded-t-lg'
              : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          <Globe className="w-4 h-4" />
          Endpoint Directory ({analysis.endpointActivity.length})
        </button>

        <button
          id="app-tab-sources"
          onClick={() => setActiveTab('sources')}
          className={`px-4 py-2.5 text-xs font-semibold border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
            activeTab === 'sources'
              ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400 bg-indigo-50/50 dark:bg-indigo-950/20 rounded-t-lg'
              : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          <Server className="w-4 h-4" />
          Source IP Analytics ({analysis.sourceIpActivity.length})
        </button>

        <button
          id="app-tab-users"
          onClick={() => setActiveTab('users')}
          className={`px-4 py-2.5 text-xs font-semibold border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
            activeTab === 'users'
              ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400 bg-indigo-50/50 dark:bg-indigo-950/20 rounded-t-lg'
              : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          <Users className="w-4 h-4" />
          User Accounts ({analysis.userActivity.length})
        </button>

        <button
          id="app-tab-timeline"
          onClick={() => setActiveTab('timeline')}
          className={`px-4 py-2.5 text-xs font-semibold border-b-2 flex items-center gap-2 whitespace-nowrap transition-colors ${
            activeTab === 'timeline'
              ? 'border-indigo-600 text-indigo-600 dark:text-indigo-400 dark:border-indigo-400 bg-indigo-50/50 dark:bg-indigo-950/20 rounded-t-lg'
              : 'border-transparent text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          <Clock className="w-4 h-4" />
          Chronological Timeline ({analysis.timeline.length})
        </button>
      </div>

      {/* Tab Panels */}
      {activeTab === 'detections' && (
        <ApplicationDetectionTable
          results={analysis.results}
          onSelectResult={res => setSelectedResult(res)}
        />
      )}

      {activeTab === 'charts' && (
        <ApplicationCharts analysis={analysis} />
      )}

      {activeTab === 'endpoints' && (
        <EndpointActivityPanel endpoints={analysis.endpointActivity} />
      )}

      {activeTab === 'sources' && (
        <SourceIpActivityPanel sourceIps={analysis.sourceIpActivity} />
      )}

      {activeTab === 'users' && (
        <UserAppActivityPanel users={analysis.userActivity} />
      )}

      {activeTab === 'timeline' && (
        <ApplicationTimeline timeline={analysis.timeline} />
      )}

      {/* Inspection Modal */}
      <ApplicationDetailModal
        result={selectedResult}
        onClose={() => setSelectedResult(null)}
      />
    </div>
  );
};
