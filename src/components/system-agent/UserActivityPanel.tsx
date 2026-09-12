import React from 'react';
import { UserActivityItem } from '../../types';
import { Users, AlertCircle, ShieldAlert, ShieldCheck } from 'lucide-react';

interface UserActivityPanelProps {
  userActivity: UserActivityItem[];
}

export const UserActivityPanel: React.FC<UserActivityPanelProps> = ({ userActivity }) => {
  return (
    <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl" id="panel-user-activity">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Users className="w-4 h-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-white font-mono">
            User Authentication & Risk Profiling
          </h3>
        </div>
        <span className="text-xs font-mono text-slate-400">
          {userActivity.length} Accounts Observed
        </span>
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-xs">
          <thead>
            <tr className="border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
              <th className="pb-2.5 font-semibold">User Account</th>
              <th className="pb-2.5 font-semibold text-center">Auth Attempts</th>
              <th className="pb-2.5 font-semibold text-center">Failed</th>
              <th className="pb-2.5 font-semibold text-center">Success</th>
              <th className="pb-2.5 font-semibold text-center">Threats</th>
              <th className="pb-2.5 font-semibold">Risk Indicator</th>
              <th className="pb-2.5 font-semibold">Operational Context</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 font-mono">
            {userActivity.length === 0 ? (
              <tr>
                <td colSpan={7} className="py-6 text-center text-slate-500">
                  No user activity recorded.
                </td>
              </tr>
            ) : (
              userActivity.map((user) => {
                const isHigh = user.riskIndicator === 'HIGH';
                const isElevated = user.riskIndicator === 'ELEVATED';

                return (
                  <tr key={user.username} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-2.5 pr-2 font-bold text-slate-200">
                      <div className="flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                        <span>{user.username}</span>
                      </div>
                    </td>
                    <td className="py-2.5 text-center text-slate-300">
                      {user.authenticationAttempts}
                    </td>
                    <td className="py-2.5 text-center">
                      <span className={user.failedAttempts > 0 ? 'text-rose-400 font-bold' : 'text-slate-500'}>
                        {user.failedAttempts}
                      </span>
                    </td>
                    <td className="py-2.5 text-center">
                      <span className={user.successfulAttempts > 0 ? 'text-emerald-400 font-bold' : 'text-slate-500'}>
                        {user.successfulAttempts}
                      </span>
                    </td>
                    <td className="py-2.5 text-center">
                      <span className={user.suspiciousEvents > 0 ? 'text-amber-400 font-bold' : 'text-slate-500'}>
                        {user.suspiciousEvents}
                      </span>
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
                          <AlertCircle className="w-3 h-3 text-amber-400" />
                        ) : (
                          <ShieldCheck className="w-3 h-3 text-slate-400" />
                        )}
                        {user.riskIndicator}
                      </span>
                    </td>
                    <td className="py-2.5 text-slate-400 font-sans text-xs max-w-xs truncate">
                      {user.reason}
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
