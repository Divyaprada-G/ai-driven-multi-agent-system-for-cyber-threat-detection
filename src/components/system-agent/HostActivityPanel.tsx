import React from 'react';
import { HostActivityItem } from '../../types';
import { Server, AlertTriangle, ShieldAlert, ShieldCheck } from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';

interface HostActivityPanelProps {
  hostActivity: HostActivityItem[];
}

export const HostActivityPanel: React.FC<HostActivityPanelProps> = ({ hostActivity }) => {
  return (
    <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl" id="panel-host-activity">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Server className="w-4 h-4 text-indigo-400" />
          <h3 className="text-sm font-semibold text-white font-mono">
            Host Activity & Endpoint Telemetry
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          {hostActivity.length} Endpoints Monitored
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
              <th className="pb-2.5 font-semibold">Endpoint / Host</th>
              <th className="pb-2.5 font-semibold text-center">Total Events</th>
              <th className="pb-2.5 font-semibold text-center">Auth Events</th>
              <th className="pb-2.5 font-semibold text-center">Processes</th>
              <th className="pb-2.5 font-semibold text-center">Threats</th>
              <th className="pb-2.5 font-semibold">Highest Severity</th>
              <th className="pb-2.5 font-semibold">Risk Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {hostActivity.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-6 text-center text-slate-500">
                  No host endpoint telemetry recorded.
                </td>
              </tr>
            ) : (
              hostActivity.map((host) => {
                const isHigh = host.riskIndicator === 'HIGH';
                const isElevated = host.riskIndicator === 'ELEVATED';

                return (
                  <tr key={host.host} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 pr-2 font-bold text-slate-200">
                      <div className="flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
                        <span>{host.host}</span>
                      </div>
                    </td>
                    <td className="py-2.5 text-center text-slate-300">
                      {host.totalEvents}
                    </td>
                    <td className="py-2.5 text-center text-slate-400">
                      {host.authenticationEvents}
                    </td>
                    <td className="py-2.5 text-center text-slate-400">
                      {host.processEvents}
                    </td>
                    <td className="py-2.5 text-center">
                      <span className={host.suspiciousEvents > 0 ? 'text-rose-400 font-bold' : 'text-slate-500'}>
                        {host.suspiciousEvents}
                      </span>
                    </td>
                    <td className="py-2.5">
                      <SeverityBadge severity={host.highestSeverity} />
                    </td>
                    <td className="py-2.5">
                      <span
                        className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          isHigh
                            ? 'bg-rose-950/80 text-rose-300 border border-rose-800'
                            : isElevated
                            ? 'bg-amber-950/80 text-amber-300 border border-amber-800'
                            : 'bg-slate-800 text-slate-300 border border-slate-700'
                        }`}
                      >
                        {isHigh ? (
                          <ShieldAlert className="w-3 h-3 text-rose-400" />
                        ) : isElevated ? (
                          <AlertTriangle className="w-3 h-3 text-amber-400" />
                        ) : (
                          <ShieldCheck className="w-3 h-3 text-slate-400" />
                        )}
                        {host.riskIndicator}
                      </span>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
