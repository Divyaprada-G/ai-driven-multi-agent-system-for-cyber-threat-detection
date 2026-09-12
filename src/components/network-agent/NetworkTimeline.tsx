import React from 'react';
import { NetworkTimelineItem } from '../../types';
import { Clock, ShieldAlert, ArrowRight } from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';

interface NetworkTimelineProps {
  timeline: NetworkTimelineItem[];
  onSelectFinding?: (id: string) => void;
}

export const NetworkTimeline: React.FC<NetworkTimelineProps> = ({
  timeline,
  onSelectFinding
}) => {
  if (!timeline || timeline.length === 0) {
    return null;
  }

  return (
    <div className="p-5 bg-slate-900/80 border border-slate-800 rounded-xl space-y-4" id="network-timeline-section">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          Network Event Chronology & Correlation Trail
        </h3>
        <span className="text-[11px] font-mono text-slate-500">
          {timeline.length} sequential findings
        </span>
      </div>

      <div className="relative pl-6 space-y-4 border-l border-slate-800 ml-2">
        {timeline.map((item, idx) => {
          const isThreat = item.classification === 'THREAT';
          return (
            <div
              key={item.id || idx}
              onClick={() => onSelectFinding && onSelectFinding(item.id.replace('TL-', ''))}
              className="relative group cursor-pointer"
            >
              {/* Timeline marker node */}
              <div
                className={`absolute -left-[31px] top-1.5 w-3.5 h-3.5 rounded-full border-2 border-slate-950 ${
                  isThreat ? 'bg-rose-500 ring-2 ring-rose-500/20' : 'bg-amber-400 ring-2 ring-amber-400/20'
                }`}
              />

              <div className="p-3 bg-slate-950/60 hover:bg-slate-800/50 border border-slate-800/80 rounded-lg transition-colors space-y-1.5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs font-mono">
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">{item.timestamp ? item.timestamp.replace('T', ' ').substring(0, 19) : '-'}</span>
                    <span className="text-slate-600">•</span>
                    <span className="text-cyan-400 font-bold group-hover:text-cyan-300 transition-colors">
                      {item.sourceIp}
                    </span>
                    <span className="text-slate-500">→</span>
                    <span className="text-slate-300">{item.destinationIp}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={item.severity} />
                    <span
                      className={`text-[10px] px-1.5 py-0.5 rounded uppercase font-bold ${
                        isThreat
                          ? 'bg-rose-950/80 text-rose-300 border border-rose-800/60'
                          : 'bg-amber-950/80 text-amber-300 border border-amber-800/60'
                      }`}
                    >
                      {item.classification}
                    </span>
                  </div>
                </div>

                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-slate-100 font-sans">
                    {item.label}
                  </span>
                  <ArrowRight className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors shrink-0" />
                </div>

                <p className="text-[11px] text-slate-400 line-clamp-1 font-mono">
                  {item.details}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
