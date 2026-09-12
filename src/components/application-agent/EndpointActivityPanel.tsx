import React, { useState } from 'react';
import { Globe, AlertTriangle, ShieldCheck, Search, ArrowUpDown } from 'lucide-react';
import { EndpointActivityItem } from '../../types/application';

interface Props {
  endpoints: EndpointActivityItem[];
}

export const EndpointActivityPanel: React.FC<Props> = ({ endpoints }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [sortField, setSortField] = useState<'requestCount' | 'errorCount'>('requestCount');

  const filteredEndpoints = endpoints
    .filter(ep => ep.endpoint.toLowerCase().includes(searchTerm.toLowerCase()))
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
    <div id="endpoint-activity-panel" className="space-y-3">
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-cyan-500" />
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-700 dark:text-slate-300">
            Application Endpoint Surface Directory ({endpoints.length})
          </h3>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative min-w-[200px]">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search endpoint..."
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              className="w-full pl-8 pr-2.5 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-750 bg-slate-50 dark:bg-slate-800 text-slate-900 dark:text-slate-100 focus:outline-none"
            />
          </div>

          <button
            onClick={() => setSortField(f => (f === 'requestCount' ? 'errorCount' : 'requestCount'))}
            className="px-2.5 py-1.5 text-xs rounded-lg border border-slate-200 dark:border-slate-750 bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-300 flex items-center gap-1 hover:bg-slate-100 dark:hover:bg-slate-750 transition-colors"
          >
            <ArrowUpDown className="w-3 h-3" />
            Sort: {sortField === 'requestCount' ? 'Volume' : 'Errors'}
          </button>
        </div>
      </div>

      <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 shadow-sm overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-slate-50 dark:bg-slate-800/60 text-slate-500 dark:text-slate-400 border-b border-slate-200 dark:border-slate-800 font-semibold">
              <tr>
                <th className="py-2.5 px-4">Endpoint Path</th>
                <th className="py-2.5 px-3">Methods</th>
                <th className="py-2.5 px-3">Total Requests</th>
                <th className="py-2.5 px-3">Errors (4xx / 5xx)</th>
                <th className="py-2.5 px-3">Distinct Clients</th>
                <th className="py-2.5 px-3">Distinct Users</th>
                <th className="py-2.5 px-3">Risk Assessment</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800 font-mono text-slate-700 dark:text-slate-300">
              {filteredEndpoints.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-6 text-center text-slate-400 font-sans">
                    No endpoints match filter.
                  </td>
                </tr>
              ) : (
                filteredEndpoints.map(ep => (
                  <tr key={ep.endpoint} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/30">
                    <td className="py-2.5 px-4 font-semibold text-slate-900 dark:text-slate-100">
                      {ep.endpoint}
                    </td>
                    <td className="py-2.5 px-3">
                      <div className="flex flex-wrap gap-1">
                        {ep.methods.map(m => (
                          <span
                            key={m}
                            className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-slate-100 dark:bg-slate-800 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700"
                          >
                            {m}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-slate-900 dark:text-slate-100">
                      {ep.requestCount}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className={ep.errorCount > 0 ? 'text-rose-600 dark:text-rose-400 font-semibold' : 'text-slate-400'}>
                        {ep.errorCount} ({ep.status4xxCount} / {ep.status5xxCount})
                      </span>
                    </td>
                    <td className="py-2.5 px-3">{ep.uniqueIps}</td>
                    <td className="py-2.5 px-3">{ep.uniqueUsers}</td>
                    <td className="py-2.5 px-3">
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold border ${getRiskBadge(ep.riskIndicator)}`}>
                        {ep.riskIndicator}
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
