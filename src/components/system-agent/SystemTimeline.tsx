import React from 'react';
import { SystemTimelineItem } from '../../types';
import { Clock, ShieldAlert, AlertTriangle } from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';

interface SystemTimelineProps {
  timeline: SystemTimelineItem[];
}

export const SystemTimeline: React.FC<SystemTimelineProps> = ({ timeline }) => {
  return (
    <div className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl" id="system-timeline-card">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-white font-mono">
            Chronological Host & Authentication Timeline
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          {timeline.length} Sequenced Security Events
        </span>
      </div>

      {timeline.length === 0 ? (
        <div className="text-center py-8 text-xs text-slate-500 font-mono">
          No chronological security anomalies recorded.
        </div>
      ) : (
        <div className="relative pl-6 border-l-2 border-slate-800 space-y-5 my-2">
          {timeline.map((item) => {
            const isThreat = item.classification === 'THREAT';
            const formattedTime = item.timestamp.includes('T')
              ? item.timestamp.replace('T', ' ').substring(0, 19)
              : item.timestamp;

            return (
              <div key={item.id} className="relative group">
                {/* Timeline node icon */}
                <div
                  className={`absolute -left-[31px] top-1 p-1 rounded-full border ${
                    isThreat
                      ? 'bg-rose-950 border-rose-600 text-rose-400'
                      : 'bg-amber-950 border-amber-600 text-amber-400'
                  }`}
                >
                  {isThreat ? (
                    <ShieldAlert className="w-3 h-3" />
                  ) : (
                    <AlertTriangle className="w-3 h-3" />
                  )}
                </div>

                <div className="p-3 bg-slate-950/60 border border-slate-800/80 rounded-lg hover:border-slate-700 transition-colors">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 mb-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-mono font-bold text-white">
                        {item.detection}
                      </span>
                      <SeverityBadge severity={item.severity} />
                      <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                        {item.eventType}
                      </span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-400">
                      {formattedTime}
                    </span>
                  </div>

                  <div className="text-xs text-slate-300 font-mono mb-1.5 flex items-center gap-2">
                    <span className="text-indigo-400">Host: {item.host}</span>
                    <span className="text-slate-600">|</span>
                    <span className="text-emerald-400">User: {item.username}</span>
                  </div>

                  <p className="text-xs text-slate-400 leading-relaxed font-sans">
                    {item.details}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
