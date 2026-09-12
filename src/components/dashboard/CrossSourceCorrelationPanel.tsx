/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Cross-Source Correlation & Multi-Stage Attack Chain Panel
 *
 * Implements:
 * - Section 13: Correlation Analytics (Total, Strong/Medium/Weak, Single vs Multi-Agent)
 * - Section 14: Multi-Stage Attack View (Auth -> PrivEsc -> App -> Network -> Risk -> Alert)
 */

import React from 'react';
import {
  Layers,
  Network,
  Server,
  Globe,
  ArrowRight,
  ShieldAlert,
  Flame,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Info
} from 'lucide-react';
import { CorrelatedEvent } from '../../types';
import { SeverityBadge } from '../common/SeverityBadge';

interface CorrelationStats {
  totalCorrelations: number;
  strong: number;
  medium: number;
  weak: number;
  singleAgent: number;
  multiAgent: number;
  multiStageChains: CorrelatedEvent[];
}

interface CrossSourceCorrelationPanelProps {
  stats: CorrelationStats;
  onSelectCorrelation?: (corr: CorrelatedEvent) => void;
}

export const CrossSourceCorrelationPanel: React.FC<CrossSourceCorrelationPanelProps> = ({
  stats,
  onSelectCorrelation
}) => {
  return (
    <div className="space-y-4">
      {/* Correlation Summary Metrics (Section 13) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 shadow">
          <span className="text-[10px] text-slate-500 uppercase font-mono block">Total Correlated</span>
          <div className="text-2xl font-bold font-mono text-cyan-400 mt-1">
            {stats.totalCorrelations}
          </div>
          <span className="text-[9px] text-slate-500 font-mono mt-0.5 block">Graph Clusters</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 shadow">
          <span className="text-[10px] text-slate-500 uppercase font-mono block">Strong Correlations</span>
          <div className="text-2xl font-bold font-mono text-rose-400 mt-1">
            {stats.strong}
          </div>
          <span className="text-[9px] text-rose-500/80 font-mono mt-0.5 block">Confidence &gt;= 85%</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 shadow">
          <span className="text-[10px] text-slate-500 uppercase font-mono block">Medium Strength</span>
          <div className="text-2xl font-bold font-mono text-amber-400 mt-1">
            {stats.medium}
          </div>
          <span className="text-[9px] text-amber-500/80 font-mono mt-0.5 block">60% - 84% Match</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 shadow">
          <span className="text-[10px] text-slate-500 uppercase font-mono block">Weak Strength</span>
          <div className="text-2xl font-bold font-mono text-slate-400 mt-1">
            {stats.weak}
          </div>
          <span className="text-[9px] text-slate-500 font-mono mt-0.5 block">&lt; 60% Match</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 shadow">
          <span className="text-[10px] text-slate-500 uppercase font-mono block">Multi-Agent Events</span>
          <div className="text-2xl font-bold font-mono text-indigo-400 mt-1">
            {stats.multiAgent}
          </div>
          <span className="text-[9px] text-indigo-400/80 font-mono mt-0.5 block">2+ Specialized Agents</span>
        </div>

        <div className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 shadow">
          <span className="text-[10px] text-slate-500 uppercase font-mono block">Single-Agent Events</span>
          <div className="text-2xl font-bold font-mono text-slate-300 mt-1">
            {stats.singleAgent}
          </div>
          <span className="text-[9px] text-slate-500 font-mono mt-0.5 block">Isolated Findings</span>
        </div>
      </div>

      {/* Multi-Stage Attack View (Section 14) */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow space-y-4">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-rose-500" />
            <h3 className="text-sm font-bold font-mono text-white">
              Multi-Stage Attack Chain View (Cross-Agent Correlation)
            </h3>
          </div>
          <span className="text-[10px] font-mono text-slate-400">
            Chronological Progression: Ingress Scan &rarr; Web Exploit &rarr; Host Token Escalation &rarr; Risk &rarr; Alert
          </span>
        </div>

        {stats.multiStageChains.length === 0 ? (
          <div className="py-10 text-center text-slate-500 font-mono text-xs bg-slate-950/60 rounded-lg border border-dashed border-slate-800">
            No multi-stage attack sequences currently correlated.
          </div>
        ) : (
          <div className="space-y-4">
            {stats.multiStageChains.map((chain, cIdx) => (
              <div
                key={chain.id || cIdx}
                className="p-4 bg-slate-950 border border-slate-800 rounded-lg space-y-3 font-mono text-xs"
              >
                {/* Header */}
                <div className="flex items-center justify-between flex-wrap gap-2 pb-2 border-b border-slate-800/80">
                  <div className="flex items-center gap-2">
                    <span className="text-cyan-400 font-bold">{chain.id}</span>
                    <span className="text-white font-bold">{chain.title}</span>
                    <SeverityBadge severity={chain.severity} />
                  </div>
                  <div className="flex items-center gap-3 text-[11px] text-slate-400">
                    <span>Duration: <strong className="text-slate-200">{chain.duration || '1m 15s'}</strong></span>
                    <span>Confidence: <strong className="text-cyan-400">{chain.confidence}%</strong></span>
                  </div>
                </div>

                {/* Killchain Pipeline Diagram (Section 14) */}
                <div className="grid grid-cols-1 md:grid-cols-5 gap-2 relative">
                  {/* Step 1: Reconnaissance / Network */}
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800 space-y-1">
                    <div className="flex items-center gap-1.5 text-cyan-400 font-bold text-[11px]">
                      <Network className="w-3.5 h-3.5" />
                      <span>1. Ingress Scan</span>
                    </div>
                    <span className="text-[10px] text-slate-400 block">
                      Source: {chain.sourceIps?.[0] || '192.168.1.105'}
                    </span>
                    <p className="text-[10px] text-slate-500 truncate">
                      Port sweep on 48 target ports
                    </p>
                  </div>

                  {/* Step 2: Web Exploit / Application */}
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800 space-y-1">
                    <div className="flex items-center gap-1.5 text-amber-400 font-bold text-[11px]">
                      <Globe className="w-3.5 h-3.5" />
                      <span>2. Web Exploit</span>
                    </div>
                    <span className="text-[10px] text-slate-400 block">
                      Target: /api/v1/auth
                    </span>
                    <p className="text-[10px] text-slate-500 truncate">
                      UNION SELECT SQL injection
                    </p>
                  </div>

                  {/* Step 3: Privilege Escalation / System */}
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800 space-y-1">
                    <div className="flex items-center gap-1.5 text-indigo-400 font-bold text-[11px]">
                      <Server className="w-3.5 h-3.5" />
                      <span>3. Host Escalation</span>
                    </div>
                    <span className="text-[10px] text-slate-400 block">
                      Host: {chain.hosts?.[0] || 'workstation-fin-04'}
                    </span>
                    <p className="text-[10px] text-slate-500 truncate">
                      SeImpersonate token duplication
                    </p>
                  </div>

                  {/* Step 4: Risk Scoring */}
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800 space-y-1">
                    <div className="flex items-center gap-1.5 text-orange-400 font-bold text-[11px]">
                      <Flame className="w-3.5 h-3.5" />
                      <span>4. Risk Scoring</span>
                    </div>
                    <span className="text-[10px] text-slate-400 block">
                      Score: <strong className="text-rose-400">94 / 100</strong>
                    </span>
                    <p className="text-[10px] text-slate-500 truncate">
                      Assigned Priority: P1 Immediate
                    </p>
                  </div>

                  {/* Step 5: Alert / Escalation */}
                  <div className="p-2.5 rounded bg-slate-900 border border-slate-800 space-y-1">
                    <div className="flex items-center gap-1.5 text-rose-400 font-bold text-[11px]">
                      <ShieldAlert className="w-3.5 h-3.5" />
                      <span>5. Alert & Incident</span>
                    </div>
                    <span className="text-[10px] text-slate-400 block">
                      Dossier: INC-2026-0042
                    </span>
                    <p className="text-[10px] text-slate-500 truncate">
                      Dispatched to Tier-2 SOC Queue
                    </p>
                  </div>
                </div>

                {/* Evidence Details */}
                <div className="pt-2 text-[11px] text-slate-400 flex items-center justify-between">
                  <span>MITRE ATT&CK: <strong className="text-slate-300">{chain.mitreTechniqueId || 'T1046 / T1190 / T1068'}</strong></span>
                  <span className="text-slate-500">
                    Participating Agents: {chain.participatingAgents?.join(', ')}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};
