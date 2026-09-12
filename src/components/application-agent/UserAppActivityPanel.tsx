import React, { useState } from 'react';
import { Users, Search, ArrowUpDown } from 'lucide-react';
import { UserAppActivityItem } from '../../types/application';

interface Props {
  users: UserAppActivityItem[];
}

export const UserAppActivityPanel: React.FC<Props> = ({ users }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortField, setSortField] = useState<'requestCount' | 'failedRequests' | 'authFailures'>('requestCount');

  const filteredUsers = users
    .filter(u => u.username.toLowerCase().includes(searchTerm.toLowerCase()))
    .sort((a, b) => b[sortField] - a[sortField]);

  const getRiskBadge = (indicator: string) => {
    switch (indicator) {
      case 'HIGH':
        return 'bg-rose-100 text-rose-800 dark:bg-rose-950/60 dark:text-rose-300 border-rose-200 dark:border-rose-900';
      case 'ELEVATED':
        return 'bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300 border-amber-200 dark:border-amber-900';
      default:
        return 'bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-300 border-emerald-200 dark:border-emerald-900';
    }
  };

  return (
    <div id="user-app-activity-panel" className="space-y-3">
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Users className="w-4 h-4 text-violet-500" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
            Identified Application Users Activity ({users.length})
          </h3>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative min-w-[200px]">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search user..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="w-full pl-8 pr-2.5 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-750 bg-slate-50 dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none"
            />
          </div>

          <button
            onClick={() => {
              if (sortField === 'requestCount') setSortField('failedRequests');
              else if (sortField === 'failedRequests') setSortField('authFailures');
              else setSortField('requestCount');
            }}
            className="px-2.5 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-750 bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-300 flex items-center gap-1 hover:bg-slate-100 dark:hover:bg-slate-750 transition-colors"
          >
            <ArrowUpDown className="w-3 h-3" />
            Sort: {sortField === 'requestCount' ? 'Volume' : sortField === 'failedRequests' ? 'Failures' : 'Auth'}
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 dark:bg-slate-800/60 text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 font-semibold">
              <tr>
                <th className="py-2.5 px-4">User Account</th>
                <th className="py-2.5 px-3">Total Requests</th>
                <th className="py-2.5 px-3">Unique Endpoints</th>
                <th className="py-2.5 px-3">Failed Requests</th>
                <th className="py-2.5 px-3">Auth Failures</th>
                <th className="py-2.5 px-3">Suspicious Events</th>
                <th className="py-2.5 px-3">Risk Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800 font-mono text-slate-700 dark:text-slate-300">
              {filteredUsers.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-slate-400 font-sans">
                    No authenticated user identities recorded in application logs.
                  </td>
                </tr>
              ) : (
                filteredUsers.map(user => (
                  <tr key={user.username} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30">
                    <td className="py-2.5 px-4 font-semibold text-slate-900 dark:text-slate-100">
                      {user.username}
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-slate-900 dark:text-slate-100">
                      {user.requestCount}
                    </td>
                    <td className="py-2.5 px-3">{user.uniqueEndpoints}</td>
                    <td className="py-2.5 px-3">
                      <span className={user.failedRequests > 0 ? 'text-rose-600 dark:text-rose-400 font-semibold' : 'text-slate-400'}>
                        {user.failedRequests}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={user.authFailures > 0 ? 'text-amber-600 dark:text-amber-400 font-semibold' : 'text-slate-400'}>
                        {user.authFailures}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={user.suspiciousEvents > 0 ? 'text-rose-600 dark:text-rose-400 font-bold' : 'text-slate-400'}>
                        {user.suspiciousEvents}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getRiskBadge(user.riskIndicator)}`}>
                        {user.riskIndicator}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
