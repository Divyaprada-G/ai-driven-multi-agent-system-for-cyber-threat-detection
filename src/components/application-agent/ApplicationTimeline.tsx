import React from 'react';
import { Clock, ShieldAlert, Globe, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { ApplicationTimelineItem } from '../../types/application';
import { SeverityLevel } from '../../types';

interface Props {
  timeline: ApplicationTimelineItem[];
}

export const ApplicationTimeline: React.FC<Props> = ({ timeline }) => {
  const getSeverityBadge = (sev: SeverityLevel) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300 border-rose-300 dark:border-rose-800';
      case 'HIGH':
        return 'bg-orange-100 text-orange-800 dark:bg-orange-950/60 dark:text-orange-300 border-orange-300 dark:border-orange-800';
      case 'MEDIUM':
        return 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 border-amber-300 dark:border-amber-800';
      default:
        return 'bg-blue-100 text-blue-800 dark:bg-blue-950/60 dark:text-blue-300 border-blue-300 dark:border-blue-800';
    }
  };

  const getStatusBadge = (code: number) => {
    if (code >= 200 && code < 300) return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300';
    if (code === 401 || code === 403) return 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300';
    if (code >= 400 && code < 500) return 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300';
    return 'bg-red-100 text-red-800 dark:bg-red-950/60 dark:text-red-300';
  };

  return (
    <div id="application-timeline-component" className="space-y-4">
      <div className="flex items-center gap-2">
        <Clock className="w-4 h-4 text-indigo-500" />
        <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
          Chronological Application Security Event Timeline ({timeline.length})
        </h3>
      </div>

      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm p-4 sm:p-6">
        {timeline.length === 0 ? (
          <div className="py-8 text-center text-xs text-slate-400">
            No application events recorded in timeline.
          </div>
        ) : (
          <div className="relative pl-6 space-y-6 before:absolute before:left-2 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-200 dark:before:bg-slate-800">
            {timeline.map((item, idx) => (
              <div key={item.id || idx} className="relative group">
                {/* Node dot */}
                <span
                  className={`absolute -left-6 top-1.5 w-3.5 h-3.5 rounded-full border-2 border-white dark:border-slate-900 ${
                    item.classification === 'THREAT'
                      ? 'bg-rose-500 ring-2 ring-rose-500/20'
                      : item.classification === 'SUSPICIOUS'
                      ? 'bg-amber-500 ring-2 ring-amber-500/20'
                      : 'bg-indigo-500 ring-2 ring-indigo-500/20'
                  }`}
                />

                <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/40 hover:border-slate-300 dark:hover:border-slate-700 transition-colors">
                  <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
                        {item.timestamp}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${getStatusBadge(item.statusCode)}`}>
                        {item.method} {item.statusCode}
                      </span>
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getSeverityBadge(item.severity)}`}>
                        {item.severity}
                      </span>
                    </div>

                    <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400">
                      IP: <span className="text-slate-800 dark:text-slate-200">{item.sourceIp}</span>
                      {item.username && item.username !== '-' && (
                        <> | User: <span className="text-slate-800 dark:text-slate-200">{item.username}</span></>
                      )}
                    </div>
                  </div>

                  <h4 className="text-xs font-bold text-slate-900 dark:text-slate-100 mb-1 flex items-center gap-1.5">
                    <Globe className="w-3.5 h-3.5 text-slate-400" />
                    {item.endpoint} - <span className="font-sans font-medium text-slate-700 dark:text-slate-300">{item.detection}</span>
                  </h4>

                  <p className="text-xs text-slate-600 dark:text-slate-400 leading-relaxed font-sans">
                    {item.details}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
