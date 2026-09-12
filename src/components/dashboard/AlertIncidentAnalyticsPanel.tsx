/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Alert & Incident Analytics with Hierarchical Mapping
 *
 * Implements:
 * - Section 15: Alert Lifecycle & Severity Analytics
 * - Section 16: Incident Triage & Containment Analytics
 * - Section 17: Alert -> Incident Relationship visualization
 */

import React from 'react';
import {
  Bell,
  Layers,
  ShieldAlert,
  Flame,
  CheckCircle2,
  HelpCircle,
  Clock,
  ArrowRight,
  ChevronRight,
  ExternalLink
} from 'lucide-react';
import { SeverityBadge } from '../common/SeverityBadge';
import { NavPageId } from '../../types';

interface AlertIncidentData {
  alerts: {
    total: number;
    new: number;
    acknowledged: number;
    investigating: number;
    resolved: number;
    falsePositive: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  incidents: {
    total: number;
    new: number;
    investigating: number;
    contained: number;
    resolved: number;
    falsePositive: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  incidentRelationships: {
    incidentId: string;
    title: string;
    severity: string;
    priority: string;
    status: string;
    riskScore: number;
    alertCount: number;
    relatedAlerts: {
      id: string;
      title: string;
      severity: string;
      status: string;
      riskScore: number;
    }[];
  }[];
}

interface AlertIncidentAnalyticsPanelProps {
  data: AlertIncidentData;
  onNavigate?: (page: NavPageId) => void;
  onSelectIncident?: (incidentId: string) => void;
}

export const AlertIncidentAnalyticsPanel: React.FC<AlertIncidentAnalyticsPanelProps> = ({
  data,
  onNavigate,
  onSelectIncident
}) => {
  return (
    <div className="space-y-4">
      {/* 2-Column Analytics Overview: Alerts vs Incidents */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Left: Alerts Analytics (Section 15) */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Bell className="w-4 h-4 text-cyan-400" />
              <h3 className="text-sm font-bold font-mono text-white">Alert Analytics</h3>
            </div>
            <span className="text-xs font-mono font-bold text-cyan-400">
              Total: {data.alerts.total}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">New</span>
              <span className="text-sm font-bold text-blue-400">{data.alerts.new}</span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Acknowledged</span>
              <span className="text-sm font-bold text-amber-400">{data.alerts.acknowledged}</span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Investigating</span>
              <span className="text-sm font-bold text-purple-400">{data.alerts.investigating}</span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Resolved</span>
              <span className="text-sm font-bold text-emerald-400">{data.alerts.resolved}</span>
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-slate-500 uppercase">Severity:</span>
              <span className="text-rose-400 font-bold">{data.alerts.critical} Crit</span>
              <span className="text-orange-400 font-bold">{data.alerts.high} High</span>
              <span className="text-amber-400 font-bold">{data.alerts.medium} Med</span>
              <span className="text-blue-400 font-bold">{data.alerts.low} Low</span>
            </div>
            <button
              onClick={() => onNavigate && onNavigate('alerts')}
              className="text-cyan-400 hover:text-cyan-300 text-[10px] font-bold inline-flex items-center gap-1"
            >
              <span>View Alerts</span>
              <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>

        {/* Right: Incidents Analytics (Section 16) */}
        <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-purple-400" />
              <h3 className="text-sm font-bold font-mono text-white">Incident Analytics</h3>
            </div>
            <span className="text-xs font-mono font-bold text-purple-400">
              Total: {data.incidents.total}
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">New</span>
              <span className="text-sm font-bold text-blue-400">{data.incidents.new}</span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Investigating</span>
              <span className="text-sm font-bold text-amber-400">{data.incidents.investigating}</span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Contained</span>
              <span className="text-sm font-bold text-purple-400">{data.incidents.contained}</span>
            </div>
            <div className="p-2 rounded bg-slate-950 border border-slate-800">
              <span className="text-[10px] text-slate-500 uppercase block">Resolved</span>
              <span className="text-sm font-bold text-emerald-400">{data.incidents.resolved}</span>
            </div>
          </div>

          <div className="pt-2 border-t border-slate-800 flex items-center justify-between text-xs font-mono">
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-slate-500 uppercase">Severity:</span>
              <span className="text-rose-400 font-bold">{data.incidents.critical} Crit</span>
              <span className="text-orange-400 font-bold">{data.incidents.high} High</span>
              <span className="text-amber-400 font-bold">{data.incidents.medium} Med</span>
              <span className="text-blue-400 font-bold">{data.incidents.low} Low</span>
            </div>
            <button
              onClick={() => onNavigate && onNavigate('incidents')}
              className="text-purple-400 hover:text-purple-300 text-[10px] font-bold inline-flex items-center gap-1"
            >
              <span>View Dossiers</span>
              <ChevronRight className="w-3 h-3" />
            </button>
          </div>
        </div>
      </div>

      {/* Alert -> Incident Relationship Visualization (Section 17) */}
      <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow space-y-3 font-mono">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Layers className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-bold text-white">
              Alert &rarr; Incident Relationship Topology
            </h3>
          </div>
          <span className="text-[10px] text-slate-500">
            How triage alerts coalesce into formal investigation dossiers
          </span>
        </div>

        <div className="space-y-3">
          {data.incidentRelationships.map(rel => (
            <div
              key={rel.incidentId}
              className="p-3.5 bg-slate-950 border border-slate-800 rounded-lg space-y-2 text-xs"
            >
              {/* Incident Header */}
              <div className="flex items-center justify-between flex-wrap gap-2 pb-2 border-b border-slate-800/80">
                <div className="flex items-center gap-2">
                  <span className="text-purple-400 font-bold">{rel.incidentId}</span>
                  <span className="text-white font-bold">{rel.title}</span>
                  <SeverityBadge severity={rel.severity as any} />
                  <span className="px-2 py-0.5 rounded text-[10px] bg-slate-900 border border-slate-700 text-slate-300">
                    {rel.status}
                  </span>
                </div>
                <div className="flex items-center gap-3 text-[11px] text-slate-400">
                  <span>Priority: <strong className="text-rose-400">{rel.priority}</strong></span>
                  <span>Risk Score: <strong className="text-cyan-400">{rel.riskScore}/100</strong></span>
                  <span>Alerts: <strong className="text-white">{rel.alertCount}</strong></span>
                </div>
              </div>

              {/* Related Alerts list */}
              <div className="space-y-1.5 pt-1">
                <span className="text-[10px] text-slate-500 uppercase block">Grouped Alerts:</span>
                {rel.relatedAlerts.length === 0 ? (
                  <span className="text-[11px] text-slate-500 italic block">
                    No individual alerts linked directly.
                  </span>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                    {rel.relatedAlerts.map(a => (
                      <div
                        key={a.id}
                        className="p-2 bg-slate-900 border border-slate-800 rounded flex items-center justify-between text-[11px]"
                      >
                        <div className="truncate mr-2">
                          <span className="text-cyan-400 font-bold mr-1.5">{a.id}</span>
                          <span className="text-slate-300 truncate">{a.title}</span>
                        </div>
                        <SeverityBadge severity={a.severity as any} />
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
