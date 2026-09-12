import React from 'react';
import { TopTalker } from '../../types';
import { Network, Server, Info, ShieldAlert, CheckCircle, AlertTriangle } from 'lucide-react';

interface TopTalkersPanelProps {
  topSources: TopTalker[];
  topDestinations: TopTalker[];
  onSelectIp?: (ip: string) => void;
}

export const TopTalkersPanel: React.FC<TopTalkersPanelProps> = ({
  topSources,
  topDestinations,
  onSelectIp
}) => {
  return (
    <div className="space-y-4" id="network-top-talkers-panel">
      {/* Informative Guidance Banner */}
      <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-lg flex items-start gap-2.5 text-xs text-slate-400">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-slate-300">Baseline Context: </span>
          High event volume alone does not imply malicious intent. Critical infrastructure endpoints such as DNS resolvers, API gateways, load balancers, and NTP time servers routinely generate high connection counts. Risk indicators evaluate behavioral patterns (port diversity, target dispersion, failure rates) rather than raw event volume alone.
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Top Source IPs */}
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
              <Network className="w-4 h-4 text-cyan-400" />
              Top Source Emitters
            </h3>
            <span className="text-[11px] font-mono text-slate-500">
              {topSources.length} hosts
            </span>
          </div>

          <div className="divide-y divide-slate-800/80">
            {topSources.map(talker => (
              <div
                key={talker.ip}
                onClick={() => onSelectIp && onSelectIp(talker.ip)}
                className="py-2.5 flex flex-col gap-1.5 hover:bg-slate-800/40 px-2 rounded cursor-pointer transition-colors"
              >
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-100 font-bold hover:text-cyan-400 transition-colors">
                    {talker.ip}
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">{talker.eventCount} flows</span>
                    {talker.riskIndicator === 'HIGH' ? (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-rose-950/60 border border-rose-800 text-[10px] text-rose-300 font-bold">
                        <ShieldAlert className="w-3 h-3 text-rose-400" />
                        HIGH RISK
                      </span>
                    ) : talker.riskIndicator === 'ELEVATED' ? (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-[10px] text-amber-300">
                        <AlertTriangle className="w-3 h-3 text-amber-400" />
                        ELEVATED
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-800 text-[10px] text-emerald-300">
                        <CheckCircle className="w-3 h-3 text-emerald-400" />
                        NORMAL
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span>Unique Targets: {talker.uniqueDestinations}</span>
                  <span className="truncate max-w-[240px] text-slate-500 font-mono text-[10px]" title={talker.reason}>
                    {talker.reason}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Destination IPs */}
        <div className="p-4 bg-slate-900/80 border border-slate-800 rounded-xl space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
              <Server className="w-4 h-4 text-emerald-400" />
              Top Destination Targets
            </h3>
            <span className="text-[11px] font-mono text-slate-500">
              {topDestinations.length} endpoints
            </span>
          </div>

          <div className="divide-y divide-slate-800/80">
            {topDestinations.map(talker => (
              <div
                key={talker.ip}
                onClick={() => onSelectIp && onSelectIp(talker.ip)}
                className="py-2.5 flex flex-col gap-1.5 hover:bg-slate-800/40 px-2 rounded cursor-pointer transition-colors"
              >
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="text-slate-100 font-bold hover:text-emerald-400 transition-colors">
                    {talker.ip}
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="text-slate-400">{talker.eventCount} hits</span>
                    {talker.riskIndicator === 'HIGH' ? (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-rose-950/60 border border-rose-800 text-[10px] text-rose-300 font-bold">
                        <ShieldAlert className="w-3 h-3 text-rose-400" />
                        TARGETED
                      </span>
                    ) : talker.riskIndicator === 'ELEVATED' ? (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-950/60 border border-amber-800 text-[10px] text-amber-300">
                        <AlertTriangle className="w-3 h-3 text-amber-400" />
                        ACTIVE
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-emerald-950/60 border border-emerald-800 text-[10px] text-emerald-300">
                        <CheckCircle className="w-3 h-3 text-emerald-400" />
                        NORMAL
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center justify-between text-[11px] text-slate-400">
                  <span>Unique Sources: {talker.uniqueDestinations}</span>
                  <span className="truncate max-w-[240px] text-slate-500 font-mono text-[10px]" title={talker.reason}>
                    {talker.reason}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
