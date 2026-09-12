import React, { useState, useEffect } from 'react';
import { GitMerge, ShieldAlert, ArrowDown, Cpu, Network, Globe, Flame, Layers, CheckCircle2 } from 'lucide-react';
import { CorrelatedEvent } from '../types';
import { correlationService } from '../services/correlationService';
import { SeverityBadge } from '../components/common/SeverityBadge';
import { StatusBadge } from '../components/common/StatusBadge';

export const EventCorrelationPage: React.FC = () => {
  const [correlations, setCorrelations] = useState<CorrelatedEvent[]>([]);
  const [selectedCorrelation, setSelectedCorrelation] = useState<CorrelatedEvent | null>(null);

  useEffect(() => {
    async function load() {
      const data = await correlationService.getCorrelatedEvents();
      setCorrelations(data);
      if (data.length > 0) {
        setSelectedCorrelation(data[0]);
      }
    }
    load();
  }, []);

  const handleEscalate = async (id: string) => {
    await correlationService.escalateToIncident(id);
    const refreshed = await correlationService.getCorrelatedEvents();
    setCorrelations(refreshed);
    if (selectedCorrelation?.correlationId === id) {
      setSelectedCorrelation(prev => (prev ? { ...prev, status: 'ESCALATED' } : null));
    }
  };

  return (
    <div className="space-y-6" id="page-event-correlation">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono text-cyan-400 uppercase tracking-widest">
            Cross-Domain AI Heuristic Engine
          </span>
        </div>
        <h2 className="text-xl font-bold text-white tracking-tight">
          Multi-Agent Event Correlation
        </h2>
        <p className="text-xs text-slate-400 mt-1 max-w-2xl">
          Synthesizes disparate low-level signals from the Network Agent, System Agent, and Application Agent to reconstruct cohesive multi-stage kill chains and unified security incidents.
        </p>
      </div>

      {/* 10. VISUAL CORRELATION PIPELINE REPRESENTATION */}
      <div className="p-6 bg-slate-900/80 border border-slate-800 rounded-xl space-y-4">
        <div className="flex items-center justify-between pb-3 border-b border-slate-800">
          <div>
            <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
              <Layers className="w-4 h-4 text-cyan-400" />
              Active Kill-Chain Correlation Graph
            </h3>
            <p className="text-xs text-slate-400">
              Visualizing causal dependency from reconnaissance to privilege escalation.
            </p>
          </div>
          {selectedCorrelation && (
            <span className="font-mono text-xs text-cyan-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
              Active Focus: {selectedCorrelation.correlationId}
            </span>
          )}
        </div>

        {/* Visual Pipeline Representation: Event 1 -> Event 2 -> Event 3 -> Correlated Incident */}
        <div className="flex flex-col items-center py-4 space-y-3 max-w-2xl mx-auto">
          {/* Step 1: Network Ingress */}
          <div className="w-full p-3.5 bg-slate-950 border border-cyan-500/40 rounded-xl flex items-center justify-between gap-3 shadow-lg shadow-cyan-950/20">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-cyan-950 border border-cyan-800 text-cyan-400">
                <Network className="w-5 h-5" />
              </div>
              <div>
                <div className="text-[11px] font-mono text-cyan-400 font-semibold">
                  EVENT 1: NETWORK AGENT (T1046)
                </div>
                <div className="text-xs font-bold text-slate-200">
                  Ingress Port Sweep on Perimeter DMZ
                </div>
                <div className="text-[11px] text-slate-400 font-mono">
                  Source: 192.168.1.105 • Target Port 443/80
                </div>
              </div>
            </div>
            <SeverityBadge severity="HIGH" />
          </div>

          <ArrowDown className="w-5 h-5 text-slate-500 animate-bounce" />

          {/* Step 2: Application Exploit */}
          <div className="w-full p-3.5 bg-slate-950 border border-purple-500/40 rounded-xl flex items-center justify-between gap-3 shadow-lg shadow-purple-950/20">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-950 border border-purple-800 text-purple-400">
                <Globe className="w-5 h-5" />
              </div>
              <div>
                <div className="text-[11px] font-mono text-purple-400 font-semibold">
                  EVENT 2: APPLICATION AGENT (T1190)
                </div>
                <div className="text-xs font-bold text-slate-200">
                  SQL Injection Payload on Checkout API
                </div>
                <div className="text-[11px] text-slate-400 font-mono">
                  Target: /api/v2/checkout • Payload: UNION SELECT
                </div>
              </div>
            </div>
            <SeverityBadge severity="HIGH" />
          </div>

          <ArrowDown className="w-5 h-5 text-slate-500 animate-bounce" />

          {/* Step 3: Host Privilege Elevation */}
          <div className="w-full p-3.5 bg-slate-950 border border-emerald-500/40 rounded-xl flex items-center justify-between gap-3 shadow-lg shadow-emerald-950/20">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-emerald-950 border border-emerald-800 text-emerald-400">
                <Cpu className="w-5 h-5" />
              </div>
              <div>
                <div className="text-[11px] font-mono text-emerald-400 font-semibold">
                  EVENT 3: SYSTEM AGENT (T1068)
                </div>
                <div className="text-xs font-bold text-slate-200">
                  SeImpersonate Privilege Token Duplication
                </div>
                <div className="text-[11px] text-slate-400 font-mono">
                  Host: workstation-fin-04 • Process: spoolsv.exe
                </div>
              </div>
            </div>
            <SeverityBadge severity="CRITICAL" />
          </div>

          <ArrowDown className="w-6 h-6 text-rose-400" />

          {/* Correlated Incident Output */}
          <div className="w-full p-4 bg-rose-950/40 border-2 border-rose-700/80 rounded-xl flex items-center justify-between gap-3 shadow-2xl shadow-rose-950/50">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-lg bg-rose-900/60 border border-rose-600 text-rose-300">
                <Flame className="w-6 h-6 animate-pulse" />
              </div>
              <div>
                <div className="text-xs font-mono text-rose-300 font-bold uppercase tracking-wider flex items-center gap-2">
                  SYNTHESIZED CORRELATED INCIDENT
                  <span className="px-2 py-0.5 rounded bg-rose-900/80 text-[10px] text-white">
                    CONFIDENCE: 94.8%
                  </span>
                </div>
                <div className="text-sm font-bold text-white mt-0.5">
                  Multi-Stage Infiltration & Lateral Elevation Attack
                </div>
                <div className="text-xs text-rose-200/80 font-mono mt-0.5">
                  Target: Finance Subnet • Status: Escalated to P0 Incident
                </div>
              </div>
            </div>

            <button
              id="btn-escalate-corr-chain"
              onClick={() => selectedCorrelation && handleEscalate(selectedCorrelation.correlationId)}
              className="px-3.5 py-2 rounded-lg bg-rose-600 hover:bg-rose-500 text-white text-xs font-mono font-bold transition-colors shadow-lg shadow-rose-600/30"
            >
              Escalate to Incident
            </button>
          </div>
        </div>
      </div>

      {/* Correlated Incidents Table */}
      <div className="bg-slate-900/70 border border-slate-800 rounded-xl overflow-hidden">
        <div className="p-4 border-b border-slate-800">
          <h3 className="text-sm font-bold text-white font-mono flex items-center gap-2">
            <GitMerge className="w-4 h-4 text-cyan-400" />
            Correlated Incident Clusters
          </h3>
          <p className="text-xs text-slate-400">
            Temporal and heuristic linkage across multi-agent logs.
          </p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-300 font-mono">
            <thead className="bg-slate-950/70 text-slate-400 uppercase tracking-wider text-[11px] border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Correlation ID</th>
                <th className="py-3 px-4">Events Count</th>
                <th className="py-3 px-4">Sources</th>
                <th className="py-3 px-4">Attack Pattern</th>
                <th className="py-3 px-4">Confidence</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {correlations.map(corr => (
                <tr
                  key={corr.correlationId}
                  id={`row-corr-${corr.correlationId.toLowerCase()}`}
                  onClick={() => setSelectedCorrelation(corr)}
                  className={`cursor-pointer transition-colors ${
                    selectedCorrelation?.correlationId === corr.correlationId
                      ? 'bg-slate-800/60'
                      : 'hover:bg-slate-800/30'
                  }`}
                >
                  <td className="py-3 px-4 font-bold text-cyan-400">
                    {corr.correlationId}
                  </td>

                  <td className="py-3 px-4">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700">
                      {corr.eventsCount} events
                    </span>
                  </td>

                  <td className="py-3 px-4 max-w-[200px] truncate text-slate-300">
                    {corr.sources.join(', ')}
                  </td>

                  <td className="py-3 px-4 font-sans font-medium text-slate-100 max-w-[250px] truncate">
                    {corr.attackPattern}
                  </td>

                  <td className="py-3 px-4 text-emerald-400 font-bold">
                    {corr.confidence}%
                  </td>

                  <td className="py-3 px-4">
                    <SeverityBadge severity={corr.severity} />
                  </td>

                  <td className="py-3 px-4">
                    <StatusBadge status={corr.status} />
                  </td>

                  <td className="py-3 px-4 text-right">
                    <button
                      id={`btn-escalate-${corr.correlationId.toLowerCase()}`}
                      onClick={e => {
                        e.stopPropagation();
                        handleEscalate(corr.correlationId);
                      }}
                      className="px-2.5 py-1 text-xs font-mono bg-slate-800 hover:bg-rose-900/60 hover:text-rose-200 text-slate-300 border border-slate-700 rounded transition-colors"
                    >
                      Escalate
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
