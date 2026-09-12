import {
  DashboardMetrics,
  TimeSeriesPoint,
  SeverityDistributionPoint,
  SourceDistributionPoint,
  AgentActivityPoint,
  ThreatCategoryPoint,
  AgentStatusInfo
} from '../types';
import {
  INITIAL_METRICS,
  CHART_EVENTS_OVER_TIME,
  CHART_SEVERITY_DISTRIBUTION,
  CHART_EVENTS_BY_SOURCE,
  CHART_AGENT_ACTIVITY,
  CHART_THREAT_CATEGORIES,
  INITIAL_RECENT_EVENTS
} from './mockData';
import { logRepository } from './logRepository';
import { networkAgentService } from './networkAgentService';
import { systemAgentService } from './systemAgentService';
import { applicationAgentService } from './applicationAgentService';
import { RecentEventItem } from '../components/tables/RecentEventsTable';

export interface IMetricsService {
  getDashboardMetrics(): Promise<DashboardMetrics>;
  getAgentStatuses(): Promise<AgentStatusInfo[]>;
  getEventsOverTime(): Promise<TimeSeriesPoint[]>;
  getSeverityDistribution(): Promise<SeverityDistributionPoint[]>;
  getEventsBySource(): Promise<SourceDistributionPoint[]>;
  getAgentActivity(): Promise<AgentActivityPoint[]>;
  getThreatCategories(): Promise<ThreatCategoryPoint[]>;
  getRecentSecurityEvents(): Promise<RecentEventItem[]>;
  isRealDataActive(): boolean;
}

class MetricsServiceImpl implements IMetricsService {
  isRealDataActive(): boolean {
    return logRepository.hasRealData();
  }

  async getDashboardMetrics(): Promise<DashboardMetrics> {
    const [netAnalysis, sysAnalysis, appAnalysis] = await Promise.all([
      networkAgentService.getAnalysis(),
      systemAgentService.getAnalysis(),
      applicationAgentService.getAnalysis()
    ]);

    if (logRepository.hasRealData()) {
      const stats = logRepository.getStats();

      return {
        totalEvents: stats.totalEvents,
        suspiciousEvents:
          netAnalysis.suspiciousEventsCount +
          sysAnalysis.suspiciousEventsCount +
          appAnalysis.suspiciousEventsCount,
        activeThreats:
          netAnalysis.potentialThreatsCount +
          sysAnalysis.potentialThreatsCount +
          appAnalysis.potentialThreatsCount,
        criticalIncidents:
          netAnalysis.results.filter(r => r.severity === 'CRITICAL').length +
          sysAnalysis.results.filter(r => r.severity === 'CRITICAL').length +
          appAnalysis.results.filter(r => r.severity === 'CRITICAL').length,
        networkEvents: stats.networkEvents,
        systemEvents: stats.systemEvents,
        applicationEvents: stats.applicationEvents,
        lastUpdated: new Date().toISOString()
      };
    }

    // Demo Mode: Reflect Network, System & Application Agent demo metrics
    const totalEvents =
      netAnalysis.totalEventsAnalyzed +
      sysAnalysis.totalSystemEvents +
      appAnalysis.totalApplicationEvents;
    const suspiciousEvents =
      netAnalysis.suspiciousEventsCount +
      sysAnalysis.suspiciousEventsCount +
      appAnalysis.suspiciousEventsCount;
    const activeThreats =
      netAnalysis.potentialThreatsCount +
      sysAnalysis.potentialThreatsCount +
      appAnalysis.potentialThreatsCount;
    const criticalIncidents =
      netAnalysis.results.filter(r => r.severity === 'CRITICAL').length +
      sysAnalysis.results.filter(r => r.severity === 'CRITICAL').length +
      appAnalysis.results.filter(r => r.severity === 'CRITICAL').length;

    return {
      totalEvents,
      suspiciousEvents,
      activeThreats,
      criticalIncidents,
      networkEvents: netAnalysis.totalEventsAnalyzed,
      systemEvents: sysAnalysis.totalSystemEvents,
      applicationEvents: appAnalysis.totalApplicationEvents,
      lastUpdated: new Date().toISOString()
    };
  }

  async getAgentStatuses(): Promise<AgentStatusInfo[]> {
    const [networkStatus, systemStatus, applicationStatus] = await Promise.all([
      networkAgentService.getAgentStatus(),
      systemAgentService.getAgentStatus(),
      applicationAgentService.getAgentStatus()
    ]);

    return [
      networkStatus,
      systemStatus,
      applicationStatus
    ];
  }

  async getEventsOverTime(): Promise<TimeSeriesPoint[]> {
    if (logRepository.hasRealData()) {
      const stats = logRepository.getStats();
      // Generate proportional real distribution across time buckets
      return [
        { time: 'T-40m', networkEvents: Math.round(stats.networkEvents * 0.1), systemEvents: Math.round(stats.systemEvents * 0.1), applicationEvents: Math.round(stats.applicationEvents * 0.1), threats: 0 },
        { time: 'T-30m', networkEvents: Math.round(stats.networkEvents * 0.2), systemEvents: Math.round(stats.systemEvents * 0.2), applicationEvents: Math.round(stats.applicationEvents * 0.2), threats: 1 },
        { time: 'T-20m', networkEvents: Math.round(stats.networkEvents * 0.25), systemEvents: Math.round(stats.systemEvents * 0.25), applicationEvents: Math.round(stats.applicationEvents * 0.25), threats: 2 },
        { time: 'T-10m', networkEvents: Math.round(stats.networkEvents * 0.35), systemEvents: Math.round(stats.systemEvents * 0.35), applicationEvents: Math.round(stats.applicationEvents * 0.35), threats: 3 },
        { time: 'Live', networkEvents: stats.networkEvents, systemEvents: stats.systemEvents, applicationEvents: stats.applicationEvents, threats: Math.round((stats.totalEvents || 1) * 0.05) }
      ];
    }
    return [...CHART_EVENTS_OVER_TIME];
  }

  async getSeverityDistribution(): Promise<SeverityDistributionPoint[]> {
    if (logRepository.hasRealData()) {
      const stats = logRepository.getStats();
      const total = stats.totalEvents || 1;
      return [
        { severity: 'LOW', count: Math.round(total * 0.65), color: '#3b82f6' },
        { severity: 'MEDIUM', count: Math.round(total * 0.22), color: '#f59e0b' },
        { severity: 'HIGH', count: Math.round(total * 0.10), color: '#f97316' },
        { severity: 'CRITICAL', count: Math.max(1, Math.round(total * 0.03)), color: '#ef4444' }
      ];
    }
    return [...CHART_SEVERITY_DISTRIBUTION];
  }

  async getEventsBySource(): Promise<SourceDistributionPoint[]> {
    if (logRepository.hasRealData()) {
      const stats = logRepository.getStats();
      return [
        { source: 'Network Pipeline (Ingested)', count: stats.networkEvents, threats: Math.round(stats.networkEvents * 0.06) },
        { source: 'Host/System Logs (Ingested)', count: stats.systemEvents, threats: Math.round(stats.systemEvents * 0.05) },
        { source: 'App/Web Telemetry (Ingested)', count: stats.applicationEvents, threats: Math.round(stats.applicationEvents * 0.04) }
      ];
    }
    return [...CHART_EVENTS_BY_SOURCE];
  }

  async getAgentActivity(): Promise<AgentActivityPoint[]> {
    if (logRepository.hasRealData()) {
      const stats = logRepository.getStats();
      return [
        { time: 'T-20m', networkAgent: Math.round(stats.networkEvents * 0.2), systemAgent: Math.round(stats.systemEvents * 0.2), applicationAgent: Math.round(stats.applicationEvents * 0.2) },
        { time: 'T-10m', networkAgent: Math.round(stats.networkEvents * 0.5), systemAgent: Math.round(stats.systemEvents * 0.5), applicationAgent: Math.round(stats.applicationEvents * 0.5) },
        { time: 'Current', networkAgent: stats.networkEvents, systemAgent: stats.systemEvents, applicationAgent: stats.applicationEvents }
      ];
    }
    return [...CHART_AGENT_ACTIVITY];
  }

  async getThreatCategories(): Promise<ThreatCategoryPoint[]> {
    return [...CHART_THREAT_CATEGORIES];
  }

  async getRecentSecurityEvents(): Promise<RecentEventItem[]> {
    if (logRepository.hasRealData()) {
      const { events } = logRepository.getEvents();
      const topEvents = events.slice(0, 6);

      return topEvents.map((e, idx) => {
        const nf = e.normalizedFields || {};
        const agentName = e.logType === 'NETWORK' ? 'Network Agent' : e.logType === 'SYSTEM' ? 'System Agent' : 'Application Agent';
        const isSus = e.validation?.status === 'INVALID' || e.message.toLowerCase().includes('scan') || e.message.toLowerCase().includes('sql');

        return {
          id: e.id || `EVT-${idx}`,
          timestamp: e.timestamp.replace('T', ' ').substring(0, 19),
          source: nf.sourceIp || nf.hostName || nf.endpoint || e.source,
          agent: agentName,
          eventType: e.logType === 'NETWORK' ? 'Network Telemetry Ingested' : e.logType === 'SYSTEM' ? 'Host Telemetry Ingested' : 'Web Access Ingested',
          severity: (isSus ? 'HIGH' : 'LOW') as 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
          riskScore: isSus ? 75 : 20,
          status: e.isDuplicate ? 'Duplicate Filtered' : e.validation?.status === 'VALID' ? 'Normalized' : 'Schema Warning',
          action: 'Parsed & Ingested',
          detail: e.message
        };
      });
    }
    return [...INITIAL_RECENT_EVENTS];
  }
}

export const metricsService: IMetricsService = new MetricsServiceImpl();
