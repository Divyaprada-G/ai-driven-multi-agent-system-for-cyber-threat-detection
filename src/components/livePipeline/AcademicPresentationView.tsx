import React from 'react';
import {
  FileText,
  Network,
  Cpu,
  Globe,
  GitMerge,
  ShieldAlert,
  Activity,
  Bell,
  AlertOctagon,
  ArrowRight,
  Database,
  Server,
  Sparkles,
  Info,
  CheckCircle2
} from 'lucide-react';
import { LivePipelineStatus } from '../../types/livePipeline';

interface AcademicPresentationViewProps {
  status: LivePipelineStatus;
}

export const AcademicPresentationView: React.FC<AcademicPresentationViewProps> = ({ status }) => {
  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 shadow-sm space-y-6">
      {/* Title Header */}
      <div className="border-b border-slate-800 pb-3 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
        <div>
          <div className="flex items-center space-x-2">
            <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider">
              Academic Architecture & Verification Diagram
            </h3>
            <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 font-semibold border border-emerald-500/30">
              Zero Paid APIs / Local Scikit-Learn
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-0.5">
            Sequential end-to-end dataflow from raw security telemetry to incident management.
          </p>
        </div>
        <span className="text-xs text-slate-400 font-mono">
          State: <span className={status.status === 'RUNNING' ? 'text-emerald-400 font-bold' : 'text-slate-400'}>{status.status}</span>
        </span>
      </div>

      {/* Interactive 6-Stage Pipeline Block Diagram */}
      <div className="grid grid-cols-1 md:grid-cols-6 gap-3 relative">
        {/* Node 1: Ingestion */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-16 h-16 bg-sky-500/5 rounded-bl-full pointer-events-none" />
          <div>
            <div className="flex items-center justify-between text-xs text-sky-400 font-semibold mb-2">
              <span>1. Ingestion</span>
              <FileText className="w-4 h-4" />
            </div>
            <h4 className="text-xs font-bold text-slate-200">Security Events</h4>
            <p className="text-[11px] text-slate-400 mt-1 leading-snug">
              Normalized network flows, host logs & app queries.
            </p>
          </div>
          <div className="mt-4 pt-2 border-t border-slate-900 flex items-center justify-between text-xs">
            <span className="text-slate-500">Ingested:</span>
            <span className="font-bold text-sky-400">{status.eventsReceived}</span>
          </div>
        </div>

        {/* Node 2: Multi-Agents */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-16 h-16 bg-purple-500/5 rounded-bl-full pointer-events-none" />
          <div>
            <div className="flex items-center justify-between text-xs text-purple-400 font-semibold mb-2">
              <span>2. Multi-Agent</span>
              <div className="flex -space-x-1">
                <Network className="w-3.5 h-3.5 text-sky-400" />
                <Cpu className="w-3.5 h-3.5 text-purple-400" />
                <Globe className="w-3.5 h-3.5 text-amber-400" />
              </div>
            </div>
            <h4 className="text-xs font-bold text-slate-200">Specialized Agents</h4>
            <p className="text-[11px] text-slate-400 mt-1 leading-snug">
              Network, System, & Application agents extract telemetry & domain findings.
            </p>
          </div>
          <div className="mt-4 pt-2 border-t border-slate-900 flex items-center justify-between text-xs">
            <span className="text-slate-500">Active Agents:</span>
            <span className="font-bold text-purple-400">3 Agents</span>
          </div>
        </div>

        {/* Node 3: Correlation */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-16 h-16 bg-indigo-500/5 rounded-bl-full pointer-events-none" />
          <div>
            <div className="flex items-center justify-between text-xs text-indigo-400 font-semibold mb-2">
              <span>3. Correlation</span>
              <GitMerge className="w-4 h-4" />
            </div>
            <h4 className="text-xs font-bold text-slate-200">Event Correlation</h4>
            <p className="text-[11px] text-slate-400 mt-1 leading-snug">
              Cross-source aggregation, multi-stage attack chaining, IP linking.
            </p>
          </div>
          <div className="mt-4 pt-2 border-t border-slate-900 flex items-center justify-between text-xs">
            <span className="text-slate-500">Time Window:</span>
            <span className="font-bold text-indigo-400">300s</span>
          </div>
        </div>

        {/* Node 4: Real ML Engine */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-16 h-16 bg-emerald-500/5 rounded-bl-full pointer-events-none" />
          <div>
            <div className="flex items-center justify-between text-xs text-emerald-400 font-semibold mb-2">
              <span>4. Real ML</span>
              <ShieldAlert className="w-4 h-4" />
            </div>
            <h4 className="text-xs font-bold text-slate-200">Scikit-Learn Model</h4>
            <p className="text-[11px] text-slate-400 mt-1 leading-snug">
              {status.activeModelType === 'ISOLATION_FOREST' ? 'Isolation Forest Anomaly Engine' : 'Random Forest Classifier'} with explainable feature impacts.
            </p>
          </div>
          <div className="mt-4 pt-2 border-t border-slate-900 flex items-center justify-between text-xs">
            <span className="text-slate-500">Detections:</span>
            <span className="font-bold text-rose-400">{status.threatsDetected}</span>
          </div>
        </div>

        {/* Node 5: Risk Scoring */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-16 h-16 bg-amber-500/5 rounded-bl-full pointer-events-none" />
          <div>
            <div className="flex items-center justify-between text-xs text-amber-400 font-semibold mb-2">
              <span>5. Risk Scoring</span>
              <Activity className="w-4 h-4" />
            </div>
            <h4 className="text-xs font-bold text-slate-200">7-Factor Risk Engine</h4>
            <p className="text-[11px] text-slate-400 mt-1 leading-snug">
              Quantitative scoring: Severity, Asset, Velocity, Exploitability, Blast Radius.
            </p>
          </div>
          <div className="mt-4 pt-2 border-t border-slate-900 flex items-center justify-between text-xs">
            <span className="text-slate-500">Evaluated:</span>
            <span className="font-bold text-amber-400">{status.eventsProcessed}</span>
          </div>
        </div>

        {/* Node 6: Alerts & Incidents */}
        <div className="bg-slate-950 border border-slate-800 rounded-xl p-3.5 flex flex-col justify-between relative overflow-hidden">
          <div className="absolute top-0 right-0 w-16 h-16 bg-rose-500/5 rounded-bl-full pointer-events-none" />
          <div>
            <div className="flex items-center justify-between text-xs text-rose-400 font-semibold mb-2">
              <span>6. Response</span>
              <div className="flex -space-x-1">
                <Bell className="w-3.5 h-3.5 text-amber-400" />
                <AlertOctagon className="w-3.5 h-3.5 text-rose-400" />
              </div>
            </div>
            <h4 className="text-xs font-bold text-slate-200">Alerts & Incidents</h4>
            <p className="text-[11px] text-slate-400 mt-1 leading-snug">
              Auditable alerts & incidents with non-destructive recommended actions.
            </p>
          </div>
          <div className="mt-4 pt-2 border-t border-slate-900 flex items-center justify-between text-xs">
            <span className="text-slate-500">Alerts / Incs:</span>
            <span className="font-bold text-slate-200">{status.alertsGenerated} / {status.incidentsCreated}</span>
          </div>
        </div>
      </div>

      {/* Academic Clarity & Terminology Callouts */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
        <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center space-x-2 text-xs font-semibold text-sky-400 mb-1">
            <Server className="w-3.5 h-3.5" />
            <span>LOCAL REST API</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Runs locally on your computer (FastAPI or local in-memory runner) and bridges the user interface to Scikit-Learn models. No paid external cloud or commercial SIEM subscription is required.
          </p>
        </div>

        <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center space-x-2 text-xs font-semibold text-emerald-400 mb-1">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>REAL ML MODELS</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Predictions are generated by mathematical Random Forest and Isolation Forest models trained on cybersecurity datasets (CICIDS2017 / UNSW-NB15). Predictions reflect actual statistical weights.
          </p>
        </div>

        <div className="bg-slate-950/60 border border-slate-800 rounded-lg p-3">
          <div className="flex items-center space-x-2 text-xs font-semibold text-amber-400 mb-1">
            <Sparkles className="w-3.5 h-3.5" />
            <span>SIMULATED SECURITY EVENTS</span>
          </div>
          <p className="text-[11px] text-slate-400 leading-relaxed">
            Safe synthetic security events generated locally to demonstrate live pipeline routing and ML categorization. They are labeled clearly and carry zero destructive network effects.
          </p>
        </div>
      </div>
    </div>
  );
};
