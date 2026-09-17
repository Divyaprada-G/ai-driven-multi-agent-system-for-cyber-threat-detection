/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 12: Local Real-Time Prediction API & Live Security Pipeline Page
 * 100% Free / Local / No Paid External API
 */

import React, { useState, useEffect } from 'react';
import {
  Radio,
  Sparkles,
  Server,
  Cpu,
  Layers,
  Activity,
  ShieldAlert,
  Database,
  RefreshCw,
  Sliders,
  CheckCircle2,
  Terminal,
  HelpCircle
} from 'lucide-react';
import { livePipelineService } from '../services/livePipelineService';
import { LivePipelineStatus, LiveSecurityEvent, LiveSimulatorMode } from '../types/livePipeline';
import { LivePipelineStatusCard } from '../components/livePipeline/LivePipelineStatusCard';
import { LiveTelemetryCollectorsPanel } from '../components/livePipeline/LiveTelemetryCollectorsPanel';
import { LivePipelineControls } from '../components/livePipeline/LivePipelineControls';
import { LiveEventStreamTable } from '../components/livePipeline/LiveEventStreamTable';
import { AcademicPresentationView } from '../components/livePipeline/AcademicPresentationView';
import { ModelInfoPanel } from '../components/livePipeline/ModelInfoPanel';
import { EventQueueViewer } from '../components/livePipeline/EventQueueViewer';
import { LiveTraceabilityModal } from '../components/livePipeline/LiveTraceabilityModal';
import { ProjectDemoModal } from '../components/livePipeline/ProjectDemoModal';
import { NavPageId } from '../types';

interface LivePipelinePageProps {
  onNavigate: (page: NavPageId) => void;
}

export const LivePipelinePage: React.FC<LivePipelinePageProps> = ({ onNavigate }) => {
  const [status, setStatus] = useState<LivePipelineStatus>(livePipelineService.getStatus());
  const [events, setEvents] = useState<LiveSecurityEvent[]>(livePipelineService.getEvents());
  const [queuedEvents, setQueuedEvents] = useState<LiveSecurityEvent[]>(livePipelineService.getQueuedEvents());
  const [selectedEvent, setSelectedEvent] = useState<LiveSecurityEvent | null>(null);
  const [isDemoModalOpen, setIsDemoModalOpen] = useState<boolean>(false);

  useEffect(() => {
    // Initial fetch
    setStatus(livePipelineService.getStatus());
    setEvents(livePipelineService.getEvents());
    setQueuedEvents(livePipelineService.getQueuedEvents());

    // Subscribe to real-time updates
    const unsubscribe = livePipelineService.subscribe(() => {
      setStatus(livePipelineService.getStatus());
      setEvents(livePipelineService.getEvents());
      setQueuedEvents(livePipelineService.getQueuedEvents());
    });

    return () => unsubscribe();
  }, []);

  const handleStartPipeline = () => {
    livePipelineService.startPipeline();
  };

  const handleStopPipeline = () => {
    livePipelineService.stopPipeline();
  };

  const handleStartSimulator = (rate: number, mode: LiveSimulatorMode) => {
    livePipelineService.startSimulator({ eventRate: rate, mode });
  };

  const handleStopSimulator = () => {
    livePipelineService.stopSimulator();
  };

  const handleClearEvents = () => {
    livePipelineService.clearEvents();
  };

  const handleRefreshStatus = async () => {
    await livePipelineService.checkBackendHealth();
    setStatus(livePipelineService.getStatus());
  };

  return (
    <div className="space-y-6" id="page-live-pipeline">
      {/* Top Banner Notice */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 sm:p-5 flex flex-col md:flex-row md:items-center justify-between gap-4 shadow-xl">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className={`w-2 h-2 rounded-full ${status.status === 'RUNNING' ? 'bg-emerald-400 animate-ping' : 'bg-slate-500'}`} />
            <span className="text-xs font-mono uppercase tracking-widest text-emerald-400 font-semibold">
              Live Real-Time Prediction API & Security Pipeline
            </span>
          </div>
          <h1 className="text-xl sm:text-2xl font-black tracking-tight text-white flex items-center gap-2">
            Local Multi-Agent Event Stream & Real ML Engine
          </h1>
          <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-3xl">
            100% Free & Local. Processes streaming security logs through specialized Network, System, and Application agents, correlates multi-source signals, and computes real Scikit-Learn predictions and 7-factor risk scores.
          </p>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => setIsDemoModalOpen(true)}
            className="px-3.5 py-2 rounded-lg bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 text-white text-xs font-bold flex items-center space-x-1.5 shadow-lg shadow-indigo-950/60 transition-all cursor-pointer"
          >
            <Sparkles className="w-4 h-4" />
            <span>RUN PROJECT DEMO</span>
          </button>
        </div>
      </div>

      {/* Primary Telemetry & Status Cards */}
      <LivePipelineStatusCard
        status={status}
        onRefresh={handleRefreshStatus}
        onNavigateToTraining={() => onNavigate('datasets-ml')}
      />

      {/* Real-Time Telemetry Collectors Control Panel */}
      <LiveTelemetryCollectorsPanel status={status} />

      {/* Operational Controls & Simulator Controls */}
      <LivePipelineControls
        status={status}
        onStartPipeline={handleStartPipeline}
        onStopPipeline={handleStopPipeline}
        onStartSimulator={handleStartSimulator}
        onStopSimulator={handleStopSimulator}
        onClearEvents={handleClearEvents}
        onRefreshStatus={handleRefreshStatus}
        onRunDemo={() => setIsDemoModalOpen(true)}
      />

      {/* Academic Presentation Block Diagram */}
      <AcademicPresentationView status={status} />

      {/* Model & Queue Panels Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <ModelInfoPanel onNavigateToTraining={() => onNavigate('datasets-ml')} />
        <EventQueueViewer queuedEvents={queuedEvents} status={status} />
      </div>

      {/* Real-Time Live Security Event Stream Table */}
      <LiveEventStreamTable
        events={events}
        onSelectEvent={(evt) => setSelectedEvent(evt)}
      />

      {/* End-to-End Traceability Modal */}
      <LiveTraceabilityModal
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />

      {/* Guided 12-Step Project Demo Modal */}
      <ProjectDemoModal
        isOpen={isDemoModalOpen}
        onClose={() => setIsDemoModalOpen(false)}
        status={status}
        onNavigateToTraining={() => onNavigate('datasets-ml')}
      />
    </div>
  );
};
