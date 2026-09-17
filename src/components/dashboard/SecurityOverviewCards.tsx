/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Security Overview Cards & Operational Posture Banner
 *
 * Implements:
 * - Section 4: Top-level summary cards (Total Events, Threats, Alerts, Incidents, FPs)
 * - Section 42: Security Posture Summary (Application Security Activity: LOW, MODERATE, ELEVATED, HIGH)
 * - Section 43: False Positive Analytics with exact FP rate or "N/A"
 * - Section 2 & 37: Truthful DEMO / SIMULATED DATA vs LIVE DATA labeling
 */

import React from 'react';
import {
  ShieldAlert,
  Flame,
  AlertTriangle,
  Bell,
  Activity,
  CheckCircle2,
  HelpCircle,
  Database,
  ArrowRight,
  Info,
  Layers
} from 'lucide-react';
import { SecurityOverviewData } from '../../services/unifiedAnalyticsService';
import { NavPageId } from '../../types';

interface SecurityOverviewCardsProps {
  overview?: SecurityOverviewData | null;
  isRealData: boolean;
  onNavigate?: (page: NavPageId) => void;
  onSelectQuickFilter?: (filterType: 'CRITICAL' | 'HIGH' | 'ALERTS' | 'INCIDENTS') => void;
}

export const SecurityOverviewCards: React.FC<SecurityOverviewCardsProps> = ({
  overview,
  isRealData,
  onNavigate,
  onSelectQuickFilter
}) => {
  if (!overview) {
    return null;
  }

  const getPostureColor = (posture: string) => {
    switch (posture) {
      case 'HIGH ACTIVITY':
        return {
          badge: 'bg-rose-950 text-rose-300 border-rose-800',
          dot: 'bg-rose-500',
          border: 'border-rose-900/60 bg-rose-950/20'
        };
      case 'ELEVATED ACTIVITY':
        return {
          badge: 'bg-orange-950 text-orange-300 border-orange-800',
          dot: 'bg-orange-500',
          border: 'border-orange-900/60 bg-orange-950/20'
        };
      case 'MODERATE ACTIVITY':
        return {
          badge: 'bg-amber-950 text-amber-300 border-amber-800',
          dot: 'bg-amber-500',
          border: 'border-amber-900/60 bg-amber-950/20'
        };
      case 'LOW ACTIVITY':
      default:
        return {
          badge: 'bg-emerald-950 text-emerald-300 border-emerald-800',
          dot: 'bg-emerald-500',
          border: 'border-emerald-900/60 bg-emerald-950/20'
        };
    }
  };

  const postureStyle = getPostureColor(overview.securityPosture);

  return (
    <div className="space-y-4">
      {/* Top Posture & Data Honesty Banner */}
      <div className={`p-4 rounded-xl border ${postureStyle.border} flex flex-col md:flex-row items-start md:items-center justify-between gap-3 shadow-lg`}>
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className={`w-3.5 h-3.5 rounded-full ${postureStyle.dot} animate-ping absolute inset-0`} />
            <div className={`w-3.5 h-3.5 rounded-full ${postureStyle.dot} relative`} />
          </div>
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs font-mono uppercase text-slate-400 font-semibold">
                Application Security Activity:
              </span>
              <span className={`px-2.5 py-0.5 rounded text-xs font-mono font-bold border ${postureStyle.badge}`}>
                {overview.securityPosture}
              </span>
              {/* Truthful Mode Label */}
              {isRealData ? (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-700">
                  REAL / EVALUATION DATASET
                </span>
              ) : (
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-300 border border-amber-700">
                  DEMO / SIMULATED DATA
                </span>
              )}
            </div>
            <p className="text-xs text-slate-300 font-mono mt-1">
              {overview.postureDescription}
            </p>
          </div>
        </div>

        <div className="text-right font-mono text-[11px] text-slate-400 flex items-center gap-2 self-end md:self-center">
          <span>Updated: {overview.lastUpdated}</span>
        </div>
      </div>

      {/* 8 Primary Security Overview Cards (Section 4) */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-8 gap-3">
        {/* 1. Total Events */}
        <div
          onClick={() => onNavigate && onNavigate('log-explorer')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/50 transition-all cursor-pointer group shadow"
        >
          <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono uppercase">
            <span>Total Events</span>
            <Database className="w-3.5 h-3.5 text-cyan-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-xl font-bold font-mono text-white">
            {overview.totalEvents.toLocaleString()}
          </div>
          <div className="mt-1 text-[10px] font-mono text-slate-500 flex items-center justify-between">
            <span>Ingested</span>
            <ArrowRight className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
        </div>

        {/* 2. Total Threats */}
        <div
          onClick={() => onNavigate && onNavigate('threat-detection')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-indigo-500/50 transition-all cursor-pointer group shadow"
        >
          <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono uppercase">
            <span>Threats</span>
            <ShieldAlert className="w-3.5 h-3.5 text-indigo-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-xl font-bold font-mono text-indigo-300">
            {overview.totalThreats}
          </div>
          <div className="mt-1 text-[10px] font-mono text-slate-500 flex items-center justify-between">
            <span>Classified</span>
            <ArrowRight className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
        </div>

        {/* 3. Critical Threats */}
        <div
          onClick={() => onSelectQuickFilter && onSelectQuickFilter('CRITICAL')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-rose-500/50 transition-all cursor-pointer group shadow"
        >
          <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono uppercase">
            <span>Critical</span>
            <Flame className="w-3.5 h-3.5 text-rose-500 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-xl font-bold font-mono text-rose-400">
            {overview.criticalThreats}
          </div>
          <div className="mt-1 text-[10px] font-mono text-rose-500/80 font-semibold flex items-center justify-between">
            <span>Immediate</span>
            <ArrowRight className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
        </div>

        {/* 4. High Threats */}
        <div
          onClick={() => onSelectQuickFilter && onSelectQuickFilter('HIGH')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-orange-500/50 transition-all cursor-pointer group shadow"
        >
          <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono uppercase">
            <span>High Threats</span>
            <AlertTriangle className="w-3.5 h-3.5 text-orange-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-xl font-bold font-mono text-orange-400">
            {overview.highThreats}
          </div>
          <div className="mt-1 text-[10px] font-mono text-orange-500/80 font-semibold flex items-center justify-between">
            <span>Urgent</span>
            <ArrowRight className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
        </div>

        {/* 5. Open Alerts */}
        <div
          onClick={() => onNavigate && onNavigate('alerts')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-cyan-500/50 transition-all cursor-pointer group shadow"
        >
          <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono uppercase">
            <span>Open Alerts</span>
            <Bell className="w-3.5 h-3.5 text-cyan-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-xl font-bold font-mono text-cyan-300">
            {overview.openAlerts}
          </div>
          <div className="mt-1 text-[10px] font-mono text-slate-500 flex items-center justify-between">
            <span>In Triage</span>
            <ArrowRight className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
        </div>

        {/* 6. Open Incidents */}
        <div
          onClick={() => onNavigate && onNavigate('incidents')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-purple-500/50 transition-all cursor-pointer group shadow"
        >
          <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono uppercase">
            <span>Open Incidents</span>
            <Layers className="w-3.5 h-3.5 text-purple-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-xl font-bold font-mono text-purple-300">
            {overview.openIncidents}
          </div>
          <div className="mt-1 text-[10px] font-mono text-slate-500 flex items-center justify-between">
            <span>Active Cases</span>
            <ArrowRight className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
        </div>

        {/* 7. Resolved Incidents */}
        <div
          onClick={() => onNavigate && onNavigate('incidents')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-emerald-500/50 transition-all cursor-pointer group shadow"
        >
          <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono uppercase">
            <span>Resolved</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-xl font-bold font-mono text-emerald-400">
            {overview.resolvedIncidents}
          </div>
          <div className="mt-1 text-[10px] font-mono text-slate-500 flex items-center justify-between">
            <span>Remediated</span>
            <ArrowRight className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
        </div>

        {/* 8. False Positives & Rate */}
        <div
          onClick={() => onNavigate && onNavigate('alerts')}
          className="p-3.5 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-600 transition-all cursor-pointer group shadow"
        >
          <div className="flex items-center justify-between text-slate-400 text-[10px] font-mono uppercase">
            <span>False Positives</span>
            <HelpCircle className="w-3.5 h-3.5 text-slate-400 group-hover:scale-110 transition-transform" />
          </div>
          <div className="mt-2 text-xl font-bold font-mono text-slate-300">
            {overview.falsePositives}
          </div>
          <div className="mt-1 text-[10px] font-mono text-slate-400 flex items-center justify-between">
            <span>Rate: <strong className="text-cyan-400">{overview.falsePositiveRate}</strong></span>
            <ArrowRight className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
          </div>
        </div>
      </div>
    </div>
  );
};
