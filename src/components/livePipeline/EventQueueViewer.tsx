import React from 'react';
import {
  Layers,
  Clock,
  Zap,
  Activity,
  ArrowRight,
  ListOrdered
} from 'lucide-react';
import { LiveSecurityEvent, LivePipelineStatus } from '../../types/livePipeline';

interface EventQueueViewerProps {
  queuedEvents: LiveSecurityEvent[];
  status: LivePipelineStatus;
}

export const EventQueueViewer: React.FC<EventQueueViewerProps> = ({ queuedEvents, status }) => {
  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-3 shadow-sm">
      <div className="flex items-center justify-between border-b border-slate-800 pb-2.5">
        <div className="flex items-center space-x-2">
          <ListOrdered className="w-4 h-4 text-sky-400" />
          <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider">In-Memory Event Queue</h3>
        </div>
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-semibold ${
          queuedEvents.length > 0 ? 'bg-amber-500/20 text-amber-300' : 'bg-slate-800 text-slate-400'
        }`}>
          {queuedEvents.length} Pending
        </span>
      </div>

      {queuedEvents.length === 0 ? (
        <div className="py-6 text-center text-slate-500 text-xs">
          <p>Queue is empty.</p>
          <p className="text-[10px] text-slate-600 mt-0.5">Events process instantaneously at ~{status.averageLatencyMs || 0.8}ms latency.</p>
        </div>
      ) : (
        <div className="space-y-1.5 max-h-48 overflow-y-auto font-mono text-xs">
          {queuedEvents.slice(0, 5).map((evt) => (
            <div
              key={evt.eventId}
              className="p-2 rounded bg-slate-950/60 border border-slate-800/80 flex items-center justify-between"
            >
              <div className="flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
                <span className="font-bold text-slate-200">{evt.eventId}</span>
                <span className="text-slate-500 text-[10px] capitalize">({evt.source})</span>
              </div>
              <span className="text-[10px] text-sky-400 truncate max-w-xs">{evt.eventType}</span>
            </div>
          ))}
          {queuedEvents.length > 5 && (
            <p className="text-[10px] text-slate-500 text-center pt-1">
              +{queuedEvents.length - 5} more items in buffer...
            </p>
          )}
        </div>
      )}

      {/* Latency Footer */}
      <div className="pt-2 border-t border-slate-800/80 grid grid-cols-3 gap-2 text-center text-xs">
        <div>
          <span className="text-[10px] text-slate-500 block">Min Latency</span>
          <span className="font-mono font-semibold text-emerald-400">{status.minLatencyMs}ms</span>
        </div>
        <div>
          <span className="text-[10px] text-slate-500 block">Avg Latency</span>
          <span className="font-mono font-semibold text-cyan-400">{status.averageLatencyMs}ms</span>
        </div>
        <div>
          <span className="text-[10px] text-slate-500 block">Max Latency</span>
          <span className="font-mono font-semibold text-amber-400">{status.maxLatencyMs}ms</span>
        </div>
      </div>
    </div>
  );
};
