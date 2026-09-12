/**
 * AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
 * Stage 10: Unified Chronological Event Timeline Panel
 *
 * Implements:
 * - Section 20: Unified timeline covering Log -> Finding -> Correlation -> Threat -> Risk -> Alert -> Incident
 * - Section 21: Timeline event inspection with Related ID and quick navigation
 */

import React, { useState } from 'react';
import {
  Clock,
  Database,
  Network,
  Server,
  Globe,
  Layers,
  ShieldAlert,
  Flame,
  Bell,
  CheckCircle2,
  Filter,
  ArrowRight,
  ExternalLink,
  ChevronRight
} from 'lucide-react';
import { UnifiedTimelineItem, TimelineEventType } from '../../types/analytics';
import { SeverityBadge } from '../common/SeverityBadge';
import { NavPageId } from '../../types';

interface EventTimelinePanelProps {
  events: UnifiedTimelineItem[];
  onNavigate?: (page: NavPageId) => void;
  onSelectEvent?: (event: UnifiedTimelineItem) => void;
}

export const EventTimelinePanel: React.FC<EventTimelinePanelProps> = ({
  events,
  onNavigate,
  onSelectEvent
}) => {
  const [filterType, setFilterType] = useState<'ALL' | TimelineEventType>('ALL');

  const filteredEvents = filterType === 'ALL'
    ? events
    : events.filter(e => e.eventType === filterType);

  const getEventIcon = (type: TimelineEventType) => {
    switch (type) {
      case 'LOG_RECEIVED':
        return <Database className="w-4 h-4 text-slate-400" />;
      case 'AGENT_FINDING':
        return <Network className="w-4 h-4 text-cyan-400" />;
      case 'CORRELATION_CREATED':
        return <Layers className="w-4 h-4 text-indigo-400" />;
      case 'THREAT_DETECTED':
        return <ShieldAlert className="w-4 h-4 text-rose-400" />;
      case 'RISK_ASSESSED':
        return <Flame className="w-4 h-4 text-orange-400" />;
      case 'ALERT_GENERATED':
      case 'ALERT_ACKNOWLEDGED':
        return <Bell className="w-4 h-4 text-amber-400" />;
      case 'INCIDENT_CREATED':
      case 'INVESTIGATION_STARTED':
      case 'INCIDENT_RESOLVED':
      default:
        return <CheckCircle2 className="w-4 h-4 text-emerald-400" />;
    }
  };

  const getEventColor = (type: TimelineEventType) => {
    switch (type) {
      case 'LOG_RECEIVED':
        return 'border-slate-800 bg-slate-900/60';
      case 'AGENT_FINDING':
        return 'border-cyan-800/60 bg-cyan-950/20';
      case 'CORRELATION_CREATED':
        return 'border-indigo-800/60 bg-indigo-950/20';
      case 'THREAT_DETECTED':
        return 'border-rose-800/60 bg-rose-950/20';
      case 'RISK_ASSESSED':
        return 'border-orange-800/60 bg-orange-950/20';
      case 'ALERT_GENERATED':
      case 'ALERT_ACKNOWLEDGED':
        return 'border-amber-800/60 bg-amber-950/20';
      case 'INCIDENT_CREATED':
      case 'INVESTIGATION_STARTED':
      case 'INCIDENT_RESOLVED':
      default:
        return 'border-emerald-800/60 bg-emerald-950/20';
    }
  };

  const handleNavigateToRelated = (item: UnifiedTimelineItem) => {
    if (!onNavigate) return;
    if (item.relatedType === 'ALERT') onNavigate('alerts');
    else if (item.relatedType === 'INCIDENT') onNavigate('incidents');
    else if (item.relatedType === 'RISK') onNavigate('risk-analysis');
    else if (item.relatedType === 'THREAT') onNavigate('threat-detection');
    else if (item.relatedType === 'CORRELATION') onNavigate('event-correlation');
    else if (item.relatedType === 'LOG') onNavigate('log-explorer');
  };

  return (
    <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl shadow space-y-4 font-mono">
      {/* Header & Filter Pills */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          <h3 className="text-sm font-bold text-white">
            Unified Chronological Security Timeline
          </h3>
          <span className="text-[10px] text-slate-500 font-normal">
            ({filteredEvents.length} events)
          </span>
        </div>

        {/* Filter Types */}
        <div className="flex items-center gap-1 overflow-x-auto max-w-full bg-slate-950 p-1 rounded-lg border border-slate-800 text-[10px]">
          <button
            onClick={() => setFilterType('ALL')}
            className={`px-2 py-0.5 rounded transition-colors whitespace-nowrap ${
              filterType === 'ALL'
                ? 'bg-cyan-500/20 text-cyan-300 font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            All Events
          </button>
          <button
            onClick={() => setFilterType('THREAT_DETECTED')}
            className={`px-2 py-0.5 rounded transition-colors whitespace-nowrap ${
              filterType === 'THREAT_DETECTED'
                ? 'bg-rose-500/20 text-rose-300 font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Threats
          </button>
          <button
            onClick={() => setFilterType('RISK_ASSESSED')}
            className={`px-2 py-0.5 rounded transition-colors whitespace-nowrap ${
              filterType === 'RISK_ASSESSED'
                ? 'bg-orange-500/20 text-orange-300 font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Risks
          </button>
          <button
            onClick={() => setFilterType('ALERT_GENERATED')}
            className={`px-2 py-0.5 rounded transition-colors whitespace-nowrap ${
              filterType === 'ALERT_GENERATED'
                ? 'bg-amber-500/20 text-amber-300 font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Alerts
          </button>
          <button
            onClick={() => setFilterType('INCIDENT_CREATED')}
            className={`px-2 py-0.5 rounded transition-colors whitespace-nowrap ${
              filterType === 'INCIDENT_CREATED'
                ? 'bg-purple-500/20 text-purple-300 font-bold'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            Incidents
          </button>
        </div>
      </div>

      {/* Timeline Stream */}
      {filteredEvents.length === 0 ? (
        <div className="py-12 text-center text-slate-500 text-xs">
          No events match the selected timeline filter.
        </div>
      ) : (
        <div className="relative pl-6 space-y-3 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-slate-800">
          {filteredEvents.map(item => (
            <div
              key={item.id}
              onClick={() => onSelectEvent && onSelectEvent(item)}
              className={`relative p-3 rounded-lg border transition-all hover:border-slate-600 cursor-pointer ${getEventColor(
                item.eventType
              )} group`}
            >
              {/* Timeline Bullet Node */}
              <div className="absolute -left-6 top-3.5 -translate-x-1/2 w-4 h-4 rounded-full bg-slate-950 border border-slate-700 flex items-center justify-center group-hover:scale-110 transition-transform">
                <div className="w-2 h-2 rounded-full bg-cyan-400" />
              </div>

              <div className="flex items-start justify-between gap-2 flex-wrap">
                <div className="flex items-center gap-2">
                  <div className="p-1 rounded bg-slate-900 border border-slate-800">
                    {getEventIcon(item.eventType)}
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-white font-bold text-xs">{item.title}</span>
                      <span className="text-[10px] text-slate-500 font-normal">
                        [{item.eventType.replace('_', ' ')}]
                      </span>
                    </div>
                    <span className="text-[10px] text-slate-400 block mt-0.5">
                      {item.timestamp}
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  {item.riskScore !== undefined && (
                    <span className="px-1.5 py-0.5 rounded bg-slate-900 text-cyan-400 font-bold text-[10px] border border-slate-800">
                      Score: {item.riskScore}
                    </span>
                  )}
                  {item.priority && (
                    <span className="px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 font-bold text-[10px] border border-rose-800">
                      {item.priority}
                    </span>
                  )}
                  <SeverityBadge severity={item.severity} />
                </div>
              </div>

              <p className="text-xs text-slate-300 mt-2 leading-relaxed">
                {item.description}
              </p>

              <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
                <span className="text-slate-500">
                  Related ID: <strong className="text-cyan-400">{item.relatedId || item.id}</strong>
                </span>
                <button
                  onClick={e => {
                    e.stopPropagation();
                    handleNavigateToRelated(item);
                  }}
                  className="text-cyan-400 hover:text-cyan-300 text-[10px] font-bold inline-flex items-center gap-1"
                >
                  <span>Open {item.relatedType || 'Record'}</span>
                  <ChevronRight className="w-3 h-3" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
